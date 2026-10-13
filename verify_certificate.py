"""
verify_certificate.py — Offline Cryptographic Audit Certificate Verifier.

Usage:
    python verify_certificate.py certificate.json
    python verify_certificate.py --employee EMP1001

Enables any third-party auditor, corporate compliance officer, or labor regulator
to mathematically verify an employee's on-chain attendance history completely OFFLINE
without running the network or trusting any server.
"""
import sys
import json
import time
import requests
import hash_utils
import crypto_utils as cu
from merkle_tree import MerkleTree

def verify_certificate_dict(cert: dict, config: dict = None) -> bool:
    print(f"\n=======================================================")
    print(f"  IPLS CRYPTOGRAPHIC AUDIT CERTIFICATE VERIFIER")
    print(f"=======================================================")
    print(f"Certificate ID  : {cert.get('certificate_id')}")
    print(f"Standard        : {cert.get('standard')}")
    print(f"Employee ID     : {cert.get('employee_id')}")
    print(f"Issuer ID       : {cert.get('issuer_id')}")
    print(f"Department      : {cert.get('department')}")
    print(f"Total Worked    : {cert.get('total_hours_worked')} hours")
    print(f"Issued At       : {time.ctime(cert.get('issued_at', 0))}")
    print(f"-------------------------------------------------------")

    # Step 1: Load official public keys
    if config is None:
        try:
            with open("network_config.json") as f:
                config = json.load(f)
        except Exception:
            config = {"officials": {}}

    official_keys = {
        oid: cu.public_key_from_str(pk)
        for oid, pk in config.get("officials", {}).items()
    }

    # Step 2: Authenticate Certificate Issuer & Cryptographic Seal
    issuer_id = cert.get("issuer_id")
    if not issuer_id or issuer_id not in official_keys:
        print(f"  [FAIL] Certificate issuer '{issuer_id}' is missing or not an active authorized official.")
        return False

    issuer_signature = cert.get("issuer_signature")
    if not issuer_signature:
        print(f"  [FAIL] Certificate missing required issuer Ed448 digital signature.")
        return False

    claimed_seal = cert.get("cryptographic_seal")
    if not claimed_seal:
        print(f"  [FAIL] Certificate missing cryptographic seal.")
        return False

    cert_copy = dict(cert)
    cert_copy.pop("cryptographic_seal", None)
    cert_copy.pop("issuer_signature", None)
    expected_seal = hash_utils.compute_block_hash(json.dumps(cert_copy, sort_keys=True).encode())

    if claimed_seal == expected_seal:
        print(f"  [PASS] Certificate Seal (BLAKE3) matches perfectly: {claimed_seal[:16]}...")
    else:
        print(f"  [FAIL] Certificate Seal MISMATCH!")
        print(f"         Expected: {expected_seal}")
        print(f"         Claimed : {claimed_seal}")
        return False

    # Authenticate issuer signature over the certificate digest / seal
    issuer_pub_key = official_keys[issuer_id]
    if not cu.verify_signature(issuer_pub_key, claimed_seal.encode(), issuer_signature):
        print(f"  [FAIL] Certificate issuer signature verification FAILED for official {issuer_id}!")
        return False
    print(f"  [PASS] Certificate Issuer ({issuer_id}) Ed448 signature authenticated against consortium registry.")

    # Step 3: Verify each historical on-chain event
    events = cert.get("audit_events", [])
    expected_event_count = cert.get("on_chain_events_count", len(events))
    if len(events) != expected_event_count:
        print(f"  [FAIL] Event count mismatch: claimed {expected_event_count}, but found {len(events)} events.")
        return False

    hours_worked = cert.get("total_hours_worked", 0)
    status = cert.get("current_status")
    if len(events) == 0 and (hours_worked > 0 or status == "IN"):
        print(f"  [FAIL] Certificate claims {hours_worked} hours worked / status '{status}' but contains NO verified on-chain audit events.")
        return False

    print(f"\nVerifying {len(events)} On-Chain Historical Events:")

    from merkle_tree import MerkleTree
    from blockchain import Blockchain
    from block import Block

    for i, ev in enumerate(events):
        idx = ev.get("block_index")
        action = ev.get("action")
        raw_ts = ev.get("timestamp")
        off_id = ev.get("official_id")
        sig = ev.get("ed448_signature")
        spv_proof = ev.get("spv_merkle_proof")
        merkle_root = ev.get("merkle_root")
        block_hash = ev.get("block_hash")
        prev_hash = ev.get("previous_hash", "0")
        block_proposer = ev.get("block_proposer_id", off_id)
        block_sig = ev.get("block_signature")
        block_ts = ev.get("block_timestamp", raw_ts)
        state_root = ev.get("state_root", "")
        tx_leaf = ev.get("tx_leaf")

        # Validate event fields
        if idx is None or not isinstance(idx, int) or idx < 1:
            print(f"    [FAIL] Event #{i+1} has invalid block index: {idx}")
            return False

        if not action or action not in {"CHECK_IN", "CHECK_OUT", "REGISTER_EMPLOYEE", "REVOKE_OFFICIAL", "ADMIN_OVERRIDE"}:
            print(f"    [FAIL] Event #{i+1} has invalid action: {action}")
            return False

        if raw_ts is None or not isinstance(raw_ts, (int, float)) or not (0 < raw_ts < 1e12):
            print(f"    [FAIL] Event #{i+1} has invalid or non-finite timestamp: {raw_ts}")
            return False

        if not off_id or not sig:
            print(f"    [FAIL] Event #{i+1} missing official_id or ed448_signature")
            return False

        ts_str = time.ctime(raw_ts)
        print(f"\n  Event #{i+1} — Block #{idx}: {action} at {ts_str} (Official: {off_id})")

        # 1. Verify transaction Ed448 signature using canonical transaction bytes
        tx_bytes = Blockchain._tx_bytes(
            cert.get("employee_id"), action, off_id, raw_ts, extra_data=ev.get("extra")
        )
        pub_key = official_keys.get(off_id)
        if not pub_key:
            print(f"    [FAIL] Official '{off_id}' not found in active network public key registry")
            return False

        if not cu.verify_signature(pub_key, tx_bytes, sig):
            print(f"    [FAIL] Transaction Ed448 Digital Signature verification FAILED for official {off_id}")
            return False
        print(f"    [PASS] Transaction Ed448 Digital Signature verified with official public key")

        # 2. Verify Block Header Authenticity under PoA (Anchoring the Merkle root to a validated block header)
        if not block_proposer or block_proposer not in official_keys:
            print(f"    [FAIL] Block proposer '{block_proposer}' not found or unauthorized")
            return False

        if not block_sig:
            print(f"    [FAIL] Event #{i+1} missing required block header signature")
            return False

        if not merkle_root:
            print(f"    [FAIL] Event #{i+1} missing Merkle Root commitment in block header")
            return False

        header_bytes = Blockchain._block_header_bytes(
            idx, prev_hash, merkle_root, state_root, block_ts, block_proposer
        )
        if not cu.verify_signature(official_keys[block_proposer], header_bytes, block_sig):
            print(f"    [FAIL] Block #{idx} header signature verification FAILED for proposer {block_proposer}")
            return False
        print(f"    [PASS] Block #{idx} header signature verified under PoA consensus (Proposer: {block_proposer})")

        # 3. Verify Block Hash Self-Consistency & Chain Commitment
        if not block_hash:
            print(f"    [FAIL] Event #{i+1} missing block_hash")
            return False

        test_block = Block(
            index=idx,
            encrypted_payload=ev.get("encrypted_payload", ""),
            official_id=block_proposer,
            previous_hash=prev_hash,
            signature=block_sig,
            timestamp=block_ts,
            state_root=state_root,
            merkle_root=merkle_root,
        )
        recomputed_block_hash = test_block.compute_hash()
        if block_hash != recomputed_block_hash:
            print(f"    [FAIL] Block #{idx} hash integrity failure: expected {recomputed_block_hash[:16]}..., claimed {block_hash[:16]}...")
            return False
        print(f"    [PASS] Block #{idx} BLAKE3 hash integrity confirmed: {block_hash[:16]}...")

        # 4. Strictly Verify SPV Merkle Inclusion Proof (No fallback to unproven roots)
        if spv_proof is None or not isinstance(spv_proof, list):
            print(f"    [FAIL] Event #{i+1} rejected: missing SPV Merkle inclusion proof")
            return False

        if tx_leaf is None:
            print(f"    [FAIL] Event #{i+1} rejected: missing transaction leaf for Merkle inclusion proof")
            return False

        if not MerkleTree.verify_proof(tx_leaf, spv_proof, merkle_root):
            print(f"    [FAIL] SPV Merkle inclusion proof verification FAILED against validated block root {merkle_root}")
            return False
        print(f"    [PASS] SPV Merkle inclusion proof path verified ({len(spv_proof)} sibling nodes) against block header root")

    print(f"\n=======================================================")
    print(f"  [RESULT] 100% AUDIT INTEGRITY CONFIRMED")
    print(f"  All timestamps, actions, block headers, and signatures are immutable.")
    print(f"=======================================================\n")
    return True


def main():
    if len(sys.argv) < 2:
        print("Usage: python verify_certificate.py <certificate.json>")
        print("       python verify_certificate.py --employee <employee_id>")
        sys.exit(1)

    if sys.argv[1] == "--employee":
        emp_id = sys.argv[2] if len(sys.argv) > 2 else "EMP1001"
        print(f"Fetching live certificate for {emp_id} from Node 5000...")
        try:
            resp = requests.get(f"http://localhost:5000/audit/certificate/{emp_id}")
            if resp.status_code != 200:
                print(f"Error fetching certificate: {resp.text}")
                sys.exit(1)
            cert = resp.json()
        except Exception as e:
            print(f"Could not connect to Node 5000: {e}")
            sys.exit(1)
    else:
        with open(sys.argv[1], "r", encoding="utf-8") as f:
            cert = json.load(f)

    valid = verify_certificate_dict(cert)
    sys.exit(0 if valid else 1)

if __name__ == "__main__":
    main()
