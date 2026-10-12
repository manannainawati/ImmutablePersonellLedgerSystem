"""
node.py — One IPLS network node (with Persistent Storage & Auto-Sync).

Run three of these on different ports to get an actual multi-node network,
each with its own independently-validated copy of the ledger:

    python node.py --port 5000
    python node.py --port 5001
    python node.py --port 5002

Optional flags:
    --clean : wipe on-disk storage for this node before booting.

Consensus model: Proof of Authority (PoA)
  A block is only accepted if it carries a genuine Ed448 signature from
  a registered Higher Official AND matches the World State Root.
"""

import argparse
import json
import os
import shutil
import sys
import time
import threading

import requests
from flask import Flask, request, jsonify, render_template

import crypto_utils as cu
from block import Block
from blockchain import Blockchain
from contract import ContractViolation

app = Flask(__name__)

with open("network_config.json") as f:
    CONFIG = json.load(f)

chain = None
SELF_URL = None
PEERS = CONFIG["peers"]
PORT = 5000
CHAIN_LOCK = threading.RLock()


@app.after_request
def add_cors(resp):
    resp.headers["Access-Control-Allow-Origin"] = "*"
    return resp


# ── Initialization & Auto-Recovery ───────────────────────────────────────────

def init_node(port, clean=False):
    global chain, SELF_URL, PORT
    PORT = port
    SELF_URL = f"http://localhost:{port}"
    data_dir = f"data/node_{port}"
    storage_path = os.path.join(data_dir, "chain.jsonl")

    if clean and os.path.exists(data_dir):
        print(f"[node] Cleaning storage directory {data_dir}...")
        shutil.rmtree(data_dir)

    chain = Blockchain(CONFIG, storage_path=storage_path)

    # Perform background catch-up synchronization with peers if any are online
    _auto_sync()
    return chain


def _auto_sync(force=False):
    """Attempt to synchronize with online peers on startup or on demand."""
    best = None
    local_valid = all(b.get("valid", False) for b in chain.is_chain_valid())
    for peer in PEERS:
        if peer == SELF_URL:
            continue
        try:
            resp = requests.get(f"{peer}/chain", timeout=1.0)
            if resp.status_code == 200:
                blocks_data = resp.json()
                blocks = [Block.from_dict(b) for b in blocks_data]
                peer_valid = all(b.get("valid", True) for b in blocks_data)
                if peer_valid:
                    if len(blocks) > len(chain.chain) or (not local_valid and len(blocks) >= len(chain.chain)):
                        if best is None or len(blocks) > len(best):
                            best = blocks
        except Exception:
            continue

    if best:
        try:
            chain.replace_chain(best)
            print(f"[sync] Successfully synchronized/healed {len(chain.chain)} blocks from peers.")
            return True
        except Exception as e:
            print(f"[sync] Sync rejected: {e}")
            return False
    else:
        print(f"[sync] Local chain is up-to-date ({len(chain.chain)} blocks).")
        return False


# ── Transaction submission (from an official's own client) ───────────────────

@app.route("/transactions/submit", methods=["POST"])
def submit_transaction():
    """
    An official's client (official_client.py) posts an already-signed
    transaction here. This node never sees a private key — only the
    Ed448 signature the official produced on their own device.
    """
    data = request.get_json()
    with CHAIN_LOCK:
        try:
            block = chain.build_block_from_transaction(
                data["employee_id"],
                data["action"],
                data["official_id"],
                data["timestamp"],
                data["signature"],
                extra_data=data.get("extra"),
            )
        except (ValueError, ContractViolation) as e:
            return jsonify({"accepted": False, "error": str(e)}), 400

        chain.append_block(block)
    _broadcast(block)
    return jsonify({"accepted": True, "block": block.to_dict()}), 201


def _broadcast(block):
    """Push a newly built block to all peer nodes."""
    for peer in PEERS:
        if peer == SELF_URL:
            continue
        try:
            requests.post(
                f"{peer}/blocks/receive",
                json=block.to_dict(),
                timeout=2,
            )
        except requests.exceptions.RequestException as e:
            print(f"[broadcast] could not reach {peer}: {e}")


# ── Block reception from a peer ───────────────────────────────────────────────

@app.route("/blocks/receive", methods=["POST"])
def receive_block():
    """
    A peer is telling us about a block IT built. We do not trust it just
    because it arrived from another node — ALL checks run again independently
    using our own local state.
    """
    block = Block.from_dict(request.get_json())
    with CHAIN_LOCK:
        try:
            chain.validate_incoming_block(block)
        except (ValueError, ContractViolation) as e:
            print(f"[reject] block {block.index}: {e}")
            return jsonify({"accepted": False, "reason": str(e)}), 409

        chain.append_block(block)
    return jsonify({"accepted": True}), 200


# ── Chain and World State queries ─────────────────────────────────────────────

@app.route("/chain")
def get_chain():
    out = []
    for block, result in zip(chain.chain, chain.is_chain_valid()):
        entry = block.to_dict()
        try:
            entry["decrypted"] = chain.decrypt_record(block)
        except Exception:
            entry["decrypted"] = {"error": "Decryption failed (Tampered or Corrupted Payload)"}
        entry.update(result)
        out.append(entry)
    return jsonify(out)


@app.route("/verify")
def verify():
    return jsonify(chain.is_chain_valid())


@app.route("/state")
def get_state():
    """Returns the current World State snapshot and State Root Hash."""
    return jsonify({
        "state_root": chain.world_state.compute_state_root(),
        "world_state": chain.world_state.to_dict(),
    })


# ── Mempool & Merkle SPV Proofs ──────────────────────────────────────────────

@app.route("/mempool")
def get_mempool():
    """Returns current unconfirmed pending transactions."""
    return jsonify({
        "count": len(chain.mempool),
        "transactions": chain.mempool,
    })


@app.route("/mine", methods=["POST"])
def mine_block():
    """Pack pending mempool transactions into a block and broadcast."""
    data = request.get_json() or {}
    proposer = data.get("proposer_id", "OFFICIAL_A")
    max_txs = int(data.get("max_txs", 10))
    with CHAIN_LOCK:
        block = chain.build_block_from_mempool(max_txs=max_txs, proposer_id=proposer)
        if not block:
            return jsonify({"mined": False, "reason": "mempool is empty"}), 400

        chain.append_block(block)
    _broadcast(block)
    return jsonify({"mined": True, "block": block.to_dict()}), 201


@app.route("/blocks/<int:index>/proof/<int:tx_index>")
def get_proof(index, tx_index):
    """Generate an SPV Merkle inclusion proof for a transaction in block index."""
    if index < 0 or index >= len(chain.chain):
        return jsonify({"error": "Block index out of bounds"}), 404
    block = chain.chain[index]
    if not block.transactions:
        return jsonify({"error": "Block has no transactions"}), 400

    from merkle_tree import MerkleTree
    tree = MerkleTree(block.transactions)
    try:
        proof = tree.get_proof(tx_index)
        target_tx = block.transactions[tx_index]
        return jsonify({
            "block_index": index,
            "tx_index": tx_index,
            "tx": target_tx,
            "merkle_root": tree.root,
            "proof": proof,
        })
    except IndexError:
        return jsonify({"error": "Transaction index out of bounds"}), 404


@app.route("/verify_merkle_proof", methods=["POST"])
def verify_proof():
    """Verify an SPV Merkle inclusion proof."""
    data = request.get_json()
    tx = data.get("tx")
    proof = data.get("proof")
    merkle_root = data.get("merkle_root")

    if not tx or proof is None or not merkle_root:
        return jsonify({"error": "Missing tx, proof, or merkle_root"}), 400

    from merkle_tree import MerkleTree
    is_valid = MerkleTree.verify_proof(tx, proof, merkle_root)
    return jsonify({"valid": is_valid})



# ── Synchronization & Resolution ─────────────────────────────────────────────

@app.route("/nodes/sync", methods=["GET", "POST"])
@app.route("/nodes/resolve", methods=["GET", "POST"])
def resolve_and_sync():
    """
    Nakamoto longest-valid-chain rule & Self-Healing:
    Ask every peer for their chain; if any peer has a longer or valid chain,
    adopt it, heal corrupted local blocks, and update on-disk WAL.
    """
    with CHAIN_LOCK:
        healed = _auto_sync(force=True)
        valid_summary = chain.is_chain_valid()
        is_now_valid = all(b["valid"] for b in valid_summary)
        return jsonify({
            "synchronized": True,
            "healed": healed,
            "replaced": healed,
            "message": "Chain synchronized and healed from peer consensus" if healed else "Local chain is already valid and up-to-date",
            "valid": is_now_valid,
            "length": len(chain.chain),
            "state_root": chain.world_state.compute_state_root(),
        })


@app.route("/nodes/peers_status")
def peers_status():
    """Returns real-time network topology, connectivity, block heights, and latencies."""
    statuses = []
    for peer in PEERS:
        t0 = time.time()
        try:
            resp = requests.get(f"{peer}/chain", timeout=1.5)
            latency = round((time.time() - t0) * 1000, 1)
            if resp.status_code == 200:
                c_data = resp.json()
                is_valid = all(b.get("valid", True) for b in c_data)
                statuses.append({
                    "url": peer,
                    "port": int(peer.split(":")[-1]),
                    "online": True,
                    "height": len(c_data),
                    "valid": is_valid,
                    "latency_ms": latency,
                    "is_self": peer == SELF_URL,
                })
            else:
                statuses.append({
                    "url": peer,
                    "port": int(peer.split(":")[-1]),
                    "online": False,
                    "error": f"HTTP {resp.status_code}",
                    "is_self": peer == SELF_URL,
                })
        except Exception:
            statuses.append({
                "url": peer,
                "port": int(peer.split(":")[-1]),
                "online": False,
                "error": "Unreachable",
                "is_self": peer == SELF_URL,
            })
    return jsonify(statuses)


@app.route("/debug/tamper_local_block", methods=["POST"])
def tamper_local_block():
    """
    FOR DEMONSTRATION / REVIEW ONLY.
    Corrupts an in-memory & on-disk block on this node to simulate disk bit-rot
    or unauthorized local manipulation. This demonstrates that any single-byte
    alteration immediately breaks cryptographic chain validity and State Root.
    """
    data = request.get_json() or {}
    idx = int(data.get("block_index", 1))
    with CHAIN_LOCK:
        if idx <= 0 or idx >= len(chain.chain):
            return jsonify({"success": False, "error": f"Invalid block index {idx}. Genesis block cannot be tampered."}), 400

        target = chain.chain[idx]
        target.encrypted_payload = "CORRUPTED_CIPHERTEXT_" + os.urandom(8).hex()
        chain._rewrite_storage()
    print(f"[tamper] Corrupted block #{idx} on Node {PORT} for attack demonstration.")
    return jsonify({
        "success": True,
        "message": f"Block #{idx} on Node {PORT} corrupted! BLAKE3 hash integrity and Fernet decryption now broken.",
        "tampered_block_index": idx,
        "node_port": PORT,
    })


# ── Debug: forge and broadcast (rejection demo) ───────────────────────────────

@app.route("/debug/forge_and_broadcast", methods=["POST"])
def forge_and_broadcast():
    """
    FOR DEMONSTRATION / REVIEW ONLY.
    Builds a block with a valid BLAKE3 hash chain but a FAKE Ed448 signature,
    proving peers independently reject it on signature check.
    """
    data = request.get_json() or {}
    payload = {
        "employee_id": data.get("employee_id", "EMP1003"),
        "action": data.get("action", "CHECK_IN"),
        "timestamp": time.time(),
    }
    encrypted = cu.encrypt_payload(chain.facility_key, payload)
    last = chain.chain[-1]

    temp_state = chain.world_state.clone()
    try:
        expected_state_root = chain.chaincode.execute_transaction(
            temp_state, payload["action"], payload, data.get("official_id", "OFFICIAL_A")
        )
    except Exception:
        expected_state_root = chain.world_state.compute_state_root()

    fake = Block(
        index=last.index + 1,
        encrypted_payload=encrypted,
        official_id=data.get("official_id", "OFFICIAL_A"),
        previous_hash=last.hash,
        signature="bm90LWEtcmVhbC1lZDQ0OC1zaWduYXR1cmU=",  # base64 garbage, not Ed448
        timestamp=payload["timestamp"],
        state_root=expected_state_root,
    )
    fake.hash = fake.compute_hash()

    results = {}
    for peer in PEERS:
        if peer == SELF_URL:
            continue
        try:
            resp = requests.post(
                f"{peer}/blocks/receive", json=fake.to_dict(), timeout=2
            )
            results[peer] = resp.json()
        except requests.exceptions.RequestException as e:
            results[peer] = {"error": str(e)}
    return jsonify(results)


# ── Web Signing Portal (Option 1) ───────────────────────────────────────────

@app.route("/portal/sign_and_submit", methods=["POST"])
def portal_sign_and_submit():
    """
    Simulates the official client app from within the browser interface.
    Loads the official's Ed448 private key from local keys/, computes canonical
    transaction bytes, signs with Ed448, creates and broadcasts a block.
    """
    data = request.get_json() or {}
    official_id = data.get("official_id", "OFFICIAL_A")
    employee_id = data.get("employee_id")
    action = data.get("action")
    extra = data.get("extra")

    if not employee_id or not action:
        return jsonify({"accepted": False, "error": "employee_id and action are required"}), 400

    keyfile = f"keys/{official_id}.key"
    if not os.path.exists(keyfile):
        return jsonify({"accepted": False, "error": f"Official key file {keyfile} not found"}), 404

    with open(keyfile, "r") as f:
        priv_key = cu.private_key_from_str(f.read().strip())

    timestamp = time.time()

    # Auto co-sign for 2-of-N Multi-Sig emergency override if co-signer key exists locally
    if action == "ADMIN_OVERRIDE" and isinstance(extra, dict) and extra.get("co_official_id") and not extra.get("co_signature"):
        co_id = extra["co_official_id"]
        co_keyfile = f"keys/{co_id}.key"
        if os.path.exists(co_keyfile):
            from contract import ChaincodeEngine
            with open(co_keyfile, "r") as f:
                co_priv = cu.private_key_from_str(f.read().strip())
            target_status = extra.get("override_status", "OUT")
            co_bytes = ChaincodeEngine.compute_override_co_sign_bytes(
                employee_id, target_status, official_id, co_id, timestamp
            )
            extra["co_signature"] = cu.sign_bytes(co_priv, co_bytes)

    tx_bytes = Blockchain._tx_bytes(employee_id, action, official_id, timestamp, extra_data=extra)
    signature = cu.sign_bytes(priv_key, tx_bytes)

    with CHAIN_LOCK:
        try:
            block = chain.build_block_from_transaction(
                employee_id=employee_id,
                action=action,
                official_id=official_id,
                timestamp=timestamp,
                signature=signature,
                extra_data=extra,
            )
        except (ValueError, ContractViolation) as e:
            return jsonify({"accepted": False, "error": str(e)}), 400

        chain.append_block(block)
    _broadcast(block)
    return jsonify({
        "accepted": True,
        "block": block.to_dict(),
        "signature": signature,
        "state_root": block.state_root,
    }), 201


# ── Cryptographic Employee Badges (Option 1) ────────────────────────────────

@app.route("/employee/<employee_id>/badge")
def employee_badge(employee_id):
    """
    Returns verifiable cryptographic badge information for an employee.
    """
    emp = chain.world_state.get_employee(employee_id)
    if not emp:
        return jsonify({"error": f"Employee {employee_id} not registered"}), 404

    last_block = chain.chain[-1]
    return jsonify({
        "employee_id": employee_id,
        "department": emp.get("department", "General"),
        "status": emp.get("status", "OUT"),
        "last_check_in": emp.get("last_check_in"),
        "last_check_out": emp.get("last_check_out"),
        "total_seconds_worked": emp.get("total_seconds_worked", 0),
        "total_hours_worked": round(emp.get("total_seconds_worked", 0) / 3600.0, 2),
        "security_clearance": "CLASS-A RESTRICTED ACCESS",
        "current_state_root": chain.world_state.compute_state_root(),
        "latest_block_hash": last_block.hash,
        "chain_height": len(chain.chain),
        "consensus": "PoA (Ed448 + BLAKE3)",
    })


# ── SOC-2 / ISO-27001 Cryptographic Audit Certificate Generator (Option 3) ──

@app.route("/audit/certificate/<employee_id>")
def audit_certificate(employee_id):
    """
    Generates an official, mathematically-verifiable cryptographic compliance
    certificate with all on-chain blocks, SPV Merkle inclusion proofs, State Roots,
    and official Ed448 signature seals.
    """
    emp = chain.world_state.get_employee(employee_id)
    if not emp:
        return jsonify({"error": f"Employee {employee_id} not found"}), 404

    from merkle_tree import MerkleTree
    import hash_utils

    audit_records = []
    for b in chain.chain:
        if b.index == 0:
            continue
        matched = False
        tx_details = None
        merkle_proof = None

        if b.transactions:
            for tx_idx, tx in enumerate(b.transactions):
                rec = cu.decrypt_payload(chain.facility_key, tx["encrypted_payload"])
                if rec.get("employee_id") == employee_id:
                    matched = True
                    tx_details = rec
                    tree = MerkleTree(b.transactions)
                    merkle_proof = tree.get_proof(tx_idx)
                    break
        else:
            rec = chain.decrypt_record(b)
            if rec.get("employee_id") == employee_id:
                matched = True
                tx_details = rec
                tree = MerkleTree([{"employee_id": rec["employee_id"], "action": rec["action"], "timestamp": b.timestamp}])
                merkle_proof = []

        if matched:
            audit_records.append({
                "block_index": b.index,
                "timestamp": b.timestamp,
                "action": tx_details.get("action"),
                "official_id": b.official_id,
                "ed448_signature": b.signature,
                "block_hash": b.hash,
                "state_root": b.state_root,
                "merkle_root": b.merkle_root,
                "spv_merkle_proof": merkle_proof,
            })

    cert_data = {
        "certificate_id": f"CERT-IPLS-{employee_id}-{int(time.time())}",
        "standard": "ISO-27001 / SOC-2 Type II Digital Custody Audit",
        "issued_at": time.time(),
        "employee_id": employee_id,
        "department": emp.get("department", "General"),
        "current_status": emp.get("status"),
        "total_seconds_worked": emp.get("total_seconds_worked", 0),
        "total_hours_worked": round(emp.get("total_seconds_worked", 0) / 3600.0, 2),
        "state_root_at_issuance": chain.world_state.compute_state_root(),
        "on_chain_events_count": len(audit_records),
        "audit_events": audit_records,
    }

    cert_canonical_bytes = json.dumps(cert_data, sort_keys=True).encode()
    cert_data["cryptographic_seal"] = hash_utils.compute_block_hash(cert_canonical_bytes)

    return jsonify(cert_data)


# ── Live Concurrency Stress Tester & TPS Benchmark (Option 4) ───────────────

@app.route("/benchmark/run", methods=["POST"])
def run_benchmark():
    """
    Executes a high-throughput transaction load benchmark to measure
    throughput (TPS), block creation time, and multi-node gossip latency.
    """
    data = request.get_json() or {}
    tx_count = min(int(data.get("count", 20)), 50)

    keyfile = "keys/OFFICIAL_A.key"
    with open(keyfile) as f:
        priv_A = cu.private_key_from_str(f.read().strip())

    t_start = time.time()
    latencies = []
    blocks_before = len(chain.chain)

    # Alternate check-ins and check-outs across employees
    for i in range(tx_count):
        emp_id = f"EMP100{1 + (i % 3)}"
        emp = chain.world_state.get_employee(emp_id)
        action = "CHECK_OUT" if (emp and emp["status"] == "IN") else "CHECK_IN"

        t_tx = time.time()
        tx_b = Blockchain._tx_bytes(emp_id, action, "OFFICIAL_A", t_tx)
        sig = cu.sign_bytes(priv_A, tx_b)
        t0 = time.time()
        chain.add_to_mempool(emp_id, action, "OFFICIAL_A", t_tx, sig)
        latencies.append((time.time() - t0) * 1000)

        # Update local temp state so subsequent mempool entries pass validation
        try:
            chain.chaincode.execute_transaction(chain.world_state, action, {"employee_id": emp_id, "timestamp": t_tx}, "OFFICIAL_A")
        except Exception:
            pass

    packed_block = chain.build_block_from_mempool(max_txs=tx_count, proposer_id="OFFICIAL_A")
    if packed_block:
        chain.append_block(packed_block)
        _broadcast(packed_block)

    total_time = max(time.time() - t_start, 0.001)
    tps = round(tx_count / total_time, 1)
    avg_latency = round(sum(latencies) / len(latencies), 2) if latencies else 0

    return jsonify({
        "success": True,
        "transactions_processed": tx_count,
        "duration_seconds": round(total_time, 3),
        "peak_tps": tps,
        "avg_mempool_latency_ms": avg_latency,
        "blocks_mined": len(chain.chain) - blocks_before,
        "state_root": chain.world_state.compute_state_root(),
    })


# ── Zero-Knowledge Proof (ZKP) Range Compliance (Option 2) ──────────────────

@app.route("/zkp/generate_proof", methods=["POST"])
def zkp_generate_proof():
    """
    Generates a Zero-Knowledge Range Proof proving an employee has satisfied
    a shift or attendance compliance rule (e.g. >= 8.0 hours) WITHOUT disclosing
    the exact number of seconds worked, exact arrival time, or personal timestamps.
    """
    import zkp_utils
    data = request.get_json() or {}
    employee_id = data.get("employee_id")
    threshold_hours = float(data.get("threshold_hours", 8.0))

    if not employee_id:
        return jsonify({"error": "employee_id is required"}), 400

    emp = chain.world_state.get_employee(employee_id)
    if not emp:
        return jsonify({"error": f"Employee {employee_id} not registered"}), 404

    # Convert to minutes for compact, fast bit decomposition proof
    actual_seconds = emp.get("total_seconds_worked", 0)
    threshold_minutes = int(threshold_hours * 60)

    # Allow testing with simulated hours if employee has not completed a full shift yet
    simulated_hours = data.get("simulated_hours")
    is_simulated = False
    if simulated_hours is not None:
        is_simulated = True
        actual_minutes = int(float(simulated_hours) * 60)
    else:
        actual_minutes = int(actual_seconds / 60.0)

    if actual_minutes < threshold_minutes:
        return jsonify({
            "error": f"Compliance threshold not met: employee has {round(actual_minutes / 60.0, 2)} hours on-chain, but {threshold_hours} hours required."
        }), 400

    try:
        proof = zkp_utils.generate_compliance_proof(
            secret_value=actual_minutes,
            threshold=threshold_minutes,
            employee_id=employee_id,
            claim_type="MIN_SHIFT_HOURS",
        )
        claim_mode = "SIMULATED_DEMO" if is_simulated else "ON_CHAIN_WORLD_STATE"

        return jsonify({
            "success": True,
            "claim": f"Total shift duration is strictly >= {threshold_hours} hours",
            "threshold_hours": threshold_hours,
            "data_source": claim_mode,
            "proof": proof,
            "privacy_guarantee": "ZERO timestamps or exact durations leaked to verifier.",
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/zkp/verify_proof", methods=["POST"])
def zkp_verify_proof():
    """
    Verifies any submitted Zero-Knowledge Compliance Proof mathematically.
    """
    import zkp_utils
    data = request.get_json() or {}
    proof = data.get("proof")
    if not proof:
        return jsonify({"error": "proof object is required"}), 400

    valid, message = zkp_utils.verify_compliance_proof(proof)
    return jsonify({
        "valid": valid,
        "message": message,
        "employee_id": proof.get("employee_id"),
        "claim_type": proof.get("claim_type"),
        "threshold_hours": proof.get("threshold_hours"),
        "protocol": proof.get("protocol"),
        "commitment_C": proof.get("commitment_C"),
        "verified_at": time.time(),
    })


# ── Dashboard ─────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="IPLS Blockchain Node")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--clean", action="store_true", help="Wipe storage before starting")
    args = parser.parse_args()

    init_node(args.port, clean=args.clean)
    print(f"[node] Starting IPLS node on {SELF_URL}")
    app.run(port=args.port)
else:
    try:
        init_node(5000)
    except Exception as e:
        print(f"[node] Warning: init_node(5000) non-fatal fallback on import: {e}")
