"""
blockchain.py — Core ledger logic for IPLS (Hyperledger Fabric Pattern + Mempool + BLAKE3 Merkle Trees).

This module manages the chain of blocks and enforces all security layers:
  Layer 1 — Integrity        : BLAKE3 domain-keyed hash chaining (fixed algo)
  Layer 2 — Consensus (PoA)  : Ed448 signature from a registered official per block
  Layer 3 — Confidentiality  : Fernet-encrypted employee data per block/transaction
  Layer 4 — Correctness      : Enterprise Chaincode Engine state-transition rules
  Layer 5 — World State      : Cryptographic State Root Hash committed to block header
  Layer 6 — Transaction Set  : BLAKE3 Merkle Tree Root committed to block header (SPV proof support)
  Storage — Persistence      : Write-Ahead Log (WAL) on disk per node (chain.jsonl)
"""

import os
import json
import time
import blake3
from block import Block
from contract import ChaincodeEngine, ContractEngine, ContractViolation
from world_state import WorldState
from merkle_tree import MerkleTree
import crypto_utils as cu
import hash_utils


class Blockchain:
    def __init__(self, config, storage_path=None):
        self.config = config
        self.facility_key = config["facility_key"].encode()
        self.official_public_keys = {
            oid: cu.public_key_from_str(pk)
            for oid, pk in config["officials"].items()
        }
        self.chaincode = ChaincodeEngine(
            config.get("personnel_registry", []),
            config.get("officials", {}).keys(),
            official_public_keys=self.official_public_keys,
        )
        self.contract = self.chaincode  # backward compatibility alias
        self.world_state = self.chaincode.world_state
        self.storage_path = storage_path
        self.mempool = []  # Unconfirmed, validated transactions waiting for block inclusion

        print(
            "[blockchain] consensus     : Proof of Authority (PoA)\n"
            "[blockchain] hash algo     : BLAKE3 (domain-keyed, fixed — no config knob)\n"
            "[blockchain] signature algo: Ed448  (RFC 8032, Goldilocks, 224-bit security)\n"
            "[blockchain] smart contract: Enterprise Chaincode with World State DB\n"
            "[blockchain] merkle trees  : BLAKE3 binary Merkle trees (SPV audit proofs enabled)"
        )
        if self.storage_path:
            print(f"[blockchain] persistence    : WAL Enabled ({self.storage_path})")

        # Load from disk if available, otherwise initialize genesis
        if self.storage_path and os.path.exists(self.storage_path) and os.path.getsize(self.storage_path) > 0:
            self._load_from_storage()
        else:
            self.chain = [self._create_genesis_block()]
            if self.storage_path:
                self._persist_block(self.chain[0])

    # ── Genesis ──────────────────────────────────────────────────────────────

    def _create_genesis_block(self):
        genesis = Block(
            index=0,
            encrypted_payload="GENESIS",
            official_id="SYSTEM",
            previous_hash="0",
            timestamp=0,
            state_root=self.world_state.compute_state_root(),
            merkle_root=MerkleTree(["GENESIS"]).root,
            transactions=[],
        )
        genesis.hash = genesis.compute_hash()
        return genesis

    # ── Disk Storage / WAL ───────────────────────────────────────────────────

    def _persist_block(self, block):
        """Append a single block to the on-disk WAL."""
        if not self.storage_path:
            return
        os.makedirs(os.path.dirname(os.path.abspath(self.storage_path)), exist_ok=True)
        with open(self.storage_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(block.to_dict()) + "\n")

    def _rewrite_storage(self):
        """Atomic rewrite of storage after fork resolution or catchup sync."""
        if not self.storage_path:
            return
        os.makedirs(os.path.dirname(os.path.abspath(self.storage_path)), exist_ok=True)
        tmp_path = self.storage_path + ".tmp"
        with open(tmp_path, "w", encoding="utf-8") as f:
            for block in self.chain:
                f.write(json.dumps(block.to_dict()) + "\n")
        os.replace(tmp_path, self.storage_path)

    def _load_from_storage(self):
        """Replay all blocks from on-disk JSONL WAL into chain and World State."""
        blocks = []
        with open(self.storage_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    blocks.append(Block.from_dict(json.loads(line)))

        if not blocks:
            self.chain = [self._create_genesis_block()]
            self._persist_block(self.chain[0])
            return

        genesis = blocks[0]
        if genesis.index != 0 or genesis.previous_hash != "0" or genesis.hash != genesis.compute_hash():
            raise ValueError("Corrupt genesis block in storage")

        # Replay transactions sequentially to restore World State
        corrupted_index = None
        for i in range(1, len(blocks)):
            b = blocks[i]
            prev = blocks[i - 1]
            if b.index != i or b.previous_hash != prev.hash or b.hash != b.compute_hash():
                print(f"[blockchain] Corrupt chain linkage detected at block {b.index} in storage")
                corrupted_index = i
                break

            # Block-level proposer and signature verification (Finding B)
            if not self._verify_block_proposer_and_signature(b, self.world_state):
                print(f"[blockchain] Invalid block proposer or signature at block {b.index} in storage")
                corrupted_index = i
                break

            try:
                if b.transactions:
                    if b.merkle_root != MerkleTree(b.transactions).root:
                        raise ValueError(f"Merkle root mismatch at block {b.index}")
                    for tx in b.transactions:
                        tx_record = cu.decrypt_payload(self.facility_key, tx["encrypted_payload"])

                        # Transaction metadata consistency check (Finding C)
                        if not self._verify_tx_metadata_consistency(tx, tx_record):
                            raise ValueError(f"Metadata contradiction at block {b.index}")

                        tx_bytes = self._tx_bytes(
                            tx_record["employee_id"], tx_record["action"],
                            tx["official_id"], tx_record["timestamp"],
                            extra_data=tx_record.get("extra"),
                        )
                        off_key = self.official_public_keys.get(tx["official_id"])
                        if not off_key or not cu.verify_signature(off_key, tx_bytes, tx["signature"]):
                            raise ValueError(f"Invalid transaction signature in block {b.index}")

                        tx_data = {
                            "employee_id": tx_record["employee_id"],
                            "timestamp": tx_record.get("timestamp", tx["timestamp"]),
                        }
                        if "extra" in tx_record:
                            tx_data.update(tx_record["extra"])
                        if tx.get("tx_id"):
                            tx_data["tx_id"] = tx["tx_id"]
                        self.chaincode.execute_transaction(self.world_state, tx_record["action"], tx_data, tx["official_id"])

                    if not b.state_root or b.state_root != self.world_state.compute_state_root():
                        raise ValueError(f"State root mismatch at block {b.index}")
                else:
                    record = self.decrypt_record(b)
                    tx_bytes = self._tx_bytes(
                        record["employee_id"], record["action"],
                        b.official_id, record["timestamp"],
                        extra_data=record.get("extra"),
                    )
                    off_key = self.official_public_keys.get(b.official_id)
                    if not off_key or not cu.verify_signature(off_key, tx_bytes, b.signature):
                        raise ValueError(f"Invalid signature in block {b.index}")

                    tx_data = {
                        "employee_id": record["employee_id"],
                        "timestamp": record.get("timestamp", b.timestamp),
                    }
                    if "extra" in record:
                        tx_data.update(record["extra"])
                    new_root = self.chaincode.execute_transaction(self.world_state, record["action"], tx_data, b.official_id)
                    if not b.state_root or b.state_root != new_root:
                        raise ValueError(f"State root mismatch at block {b.index}")
            except Exception as e:
                print(f"[blockchain] State replay stopped at block {b.index}: {e}")
                corrupted_index = i
                break

        if corrupted_index is not None:
            self.chain = blocks[:corrupted_index]
            print(f"[blockchain] Storage contains corrupted block(s) from index {corrupted_index}; loaded valid prefix of {len(self.chain)} blocks, awaiting peer healing.")
        else:
            self.chain = blocks
            print(f"[blockchain] Restored {len(self.chain)} blocks and World State from {self.storage_path}")

    # ── Transaction & Block Header Bytes (Canonical Format) ──────────────────

    @staticmethod
    def _tx_bytes(employee_id, action, official_id, timestamp, extra_data=None):
        payload = {
            "action": action,
            "employee_id": employee_id,
            "official_id": official_id,
            "timestamp": timestamp,
        }
        if extra_data:
            clean_extra = {k: v for k, v in extra_data.items() if k != "co_signature"}
            if clean_extra:
                payload["extra"] = clean_extra
        return json.dumps(payload, sort_keys=True).encode()

    @staticmethod
    def _block_header_bytes(index: int, previous_hash: str, merkle_root: str, state_root: str, timestamp: float, official_id: str) -> bytes:
        """Canonical block header serialization for Proof of Authority proposal signatures."""
        header = {
            "index": index,
            "merkle_root": merkle_root,
            "official_id": official_id,
            "previous_hash": previous_hash,
            "state_root": state_root,
            "timestamp": timestamp,
        }
        return json.dumps(header, sort_keys=True).encode()

    def _verify_block_proposer_and_signature(self, block, current_state) -> bool:
        """
        Verify that block.official_id is an authorized active official and
        block.signature cryptographically verifies against their public key.
        (Fixes Finding B)
        """
        if block.index == 0:
            return block.official_id == "SYSTEM" and block.signature is None

        if not block.official_id or block.official_id not in self.official_public_keys:
            return False

        if not current_state.is_official_active(block.official_id):
            return False

        if not block.signature or not isinstance(block.signature, str):
            return False

        off_pub = self.official_public_keys[block.official_id]

        # 1. Check if signature verifies over the canonical block header
        header_b = self._block_header_bytes(
            block.index, block.previous_hash, block.merkle_root, block.state_root, block.timestamp, block.official_id
        )
        if cu.verify_signature(off_pub, header_b, block.signature):
            return True

        # 2. For single-transaction blocks, check if signature verifies over the transaction payload
        if block.transactions and len(block.transactions) == 1 and block.transactions[0].get("official_id") == block.official_id:
            try:
                rec = cu.decrypt_payload(self.facility_key, block.transactions[0]["encrypted_payload"])
                tx_b = self._tx_bytes(
                    rec["employee_id"], rec["action"], block.official_id, rec["timestamp"], extra_data=rec.get("extra")
                )
                if cu.verify_signature(off_pub, tx_b, block.signature):
                    return True
            except Exception:
                pass
        elif not block.transactions and block.encrypted_payload != "GENESIS":
            try:
                rec = self.decrypt_record(block)
                tx_b = self._tx_bytes(
                    rec["employee_id"], rec["action"], block.official_id, rec["timestamp"], extra_data=rec.get("extra")
                )
                if cu.verify_signature(off_pub, tx_b, block.signature):
                    return True
            except Exception:
                pass

        return False

    def _verify_tx_metadata_consistency(self, tx: dict, record: dict) -> bool:
        """
        Guarantee that visible plaintext transaction fields in the block
        strictly match the decrypted, cryptographically-signed payload.
        (Fixes Finding C)
        """
        if tx.get("employee_id") != record.get("employee_id"):
            return False
        if tx.get("action") != record.get("action"):
            return False
        if "official_id" in record and tx.get("official_id") != record.get("official_id"):
            return False
        tx_ts = tx.get("timestamp")
        rec_ts = record.get("timestamp")
        if tx_ts is None or rec_ts is None or abs(float(tx_ts) - float(rec_ts)) > 1e-4:
            return False
        if tx.get("extra") != record.get("extra"):
            return False
        # Verify tx_id commitment if present
        tx_bytes = self._tx_bytes(
            record["employee_id"], record["action"], tx["official_id"], record["timestamp"], extra_data=record.get("extra")
        )
        expected_tx_id = blake3.blake3(tx_bytes).hexdigest()
        if tx.get("tx_id") and tx.get("tx_id") != expected_tx_id:
            return False
        return True

    def decrypt_record(self, block):
        if block.encrypted_payload == "GENESIS":
            return {"note": "genesis block"}
        return cu.decrypt_payload(self.facility_key, block.encrypted_payload)

    # ── Mempool Operations ───────────────────────────────────────────────────

    def add_to_mempool(self, employee_id, action, official_id, timestamp, signature, extra_data=None):
        """
        Validate transaction signature and contract rules sequentially, and place in mempool.
        """
        if official_id not in self.official_public_keys:
            raise ValueError(f"'{official_id}' is not a registered Higher Official")

        if not self.world_state.is_official_active(official_id):
            raise ContractViolation(f"Official '{official_id}' is REVOKED or inactive")

        tx_bytes = self._tx_bytes(employee_id, action, official_id, timestamp, extra_data=extra_data)
        if not cu.verify_signature(
            self.official_public_keys[official_id], tx_bytes, signature
        ):
            raise ValueError("Ed448 signature does not verify against official's public key")

        tx_data = {
            "employee_id": employee_id,
            "timestamp": timestamp,
        }
        if extra_data:
            tx_data.update(extra_data)

        # Sequential dry-run execution against cumulative unconfirmed mempool state
        simulated_state = self.world_state.clone()
        sim_chaincode = ChaincodeEngine(
            self.config.get("personnel_registry", []),
            self.config.get("officials", {}).keys(),
            official_public_keys=self.official_public_keys,
        )
        sim_chaincode.world_state = simulated_state

        for pending in self.mempool:
            p_data = {
                "employee_id": pending["employee_id"],
                "timestamp": pending["timestamp"],
            }
            if pending.get("extra"):
                p_data.update(pending["extra"])
            sim_chaincode.execute_transaction(simulated_state, pending["action"], p_data, pending["official_id"])

        # Validate proposed transaction against state with preceding mempool transactions applied
        sim_chaincode.execute_transaction(simulated_state, action, tx_data, official_id)

        payload = {
            "employee_id": employee_id,
            "action": action,
            "timestamp": timestamp,
        }
        if extra_data:
            payload["extra"] = extra_data
        encrypted = cu.encrypt_payload(self.facility_key, payload)

        tx_id = blake3.blake3(tx_bytes).hexdigest()
        tx_obj = {
            "tx_id": tx_id,
            "employee_id": employee_id,
            "action": action,
            "official_id": official_id,
            "timestamp": timestamp,
            "signature": signature,
            "encrypted_payload": encrypted,
            "extra": extra_data,
        }
        self.mempool.append(tx_obj)
        return tx_obj

    def build_block_from_mempool(self, max_txs=10, proposer_id="OFFICIAL_A"):
        """
        Pack pending transactions from mempool into a new multi-transaction Block.
        """
        if not self.mempool:
            return None

        batch = self.mempool[:max_txs]
        temp_state = self.world_state.clone()
        batch_chaincode = ChaincodeEngine(
            self.config.get("personnel_registry", []),
            self.config.get("officials", {}).keys(),
            official_public_keys=self.official_public_keys,
        )
        batch_chaincode.world_state = temp_state

        for tx in batch:
            tx_data = {
                "employee_id": tx["employee_id"],
                "timestamp": tx["timestamp"],
            }
            if tx.get("extra"):
                tx_data.update(tx["extra"])
            batch_chaincode.execute_transaction(
                temp_state, tx["action"], tx_data, tx["official_id"]
            )

        new_state_root = temp_state.compute_state_root()
        merkle_root = MerkleTree(batch).root
        last_block = self.chain[-1]
        now = time.time()

        # Proposer authenticates the block header under PoA (Fixes Finding B)
        block_sig = None
        key_path = f"keys/{proposer_id}.key"
        if os.path.exists(key_path):
            try:
                with open(key_path, "r", encoding="utf-8") as f:
                    proposer_priv = cu.private_key_from_str(f.read().strip())
                header_bytes = self._block_header_bytes(
                    last_block.index + 1, last_block.hash, merkle_root, new_state_root, now, proposer_id
                )
                block_sig = cu.sign_bytes(proposer_priv, header_bytes)
            except Exception:
                pass
        if not block_sig and batch:
            block_sig = batch[0]["signature"]

        block = Block(
            index=last_block.index + 1,
            encrypted_payload=batch[0]["encrypted_payload"],
            official_id=proposer_id,
            previous_hash=last_block.hash,
            signature=block_sig,
            timestamp=now,
            state_root=new_state_root,
            merkle_root=merkle_root,
            transactions=batch,
        )
        block.hash = block.compute_hash()
        return block

    # ── Path 1: Immediate Block Creation (Single Transaction) ────────────────

    def build_block_from_transaction(self, employee_id, action, official_id,
                                      timestamp, signature, extra_data=None):
        """
        Validate an already-signed transaction, execute chaincode dry-run,
        construct a Merkle tree of [transaction], and build a new Block.
        """
        if official_id not in self.official_public_keys:
            raise ValueError(f"'{official_id}' is not a registered Higher Official")

        if not self.world_state.is_official_active(official_id):
            raise ContractViolation(f"Official '{official_id}' is REVOKED or inactive")

        tx_bytes = self._tx_bytes(employee_id, action, official_id, timestamp, extra_data=extra_data)
        if not cu.verify_signature(
            self.official_public_keys[official_id], tx_bytes, signature
        ):
            raise ValueError("Ed448 signature does not verify against official's public key")

        tx_data = {
            "employee_id": employee_id,
            "timestamp": timestamp,
        }
        if extra_data:
            tx_data.update(extra_data)

        temp_state = self.world_state.clone()
        new_state_root = self.chaincode.execute_transaction(temp_state, action, tx_data, official_id)

        payload = {
            "employee_id": employee_id,
            "action": action,
            "timestamp": timestamp,
        }
        if extra_data:
            payload["extra"] = extra_data

        encrypted = cu.encrypt_payload(self.facility_key, payload)
        tx_id = blake3.blake3(tx_bytes).hexdigest()

        tx_record = {
            "tx_id": tx_id,
            "employee_id": employee_id,
            "action": action,
            "official_id": official_id,
            "timestamp": timestamp,
            "signature": signature,
            "encrypted_payload": encrypted,
            "extra": extra_data,
        }

        merkle_root = MerkleTree([tx_record]).root
        last_block = self.chain[-1]

        block = Block(
            index=last_block.index + 1,
            encrypted_payload=encrypted,
            official_id=official_id,
            previous_hash=last_block.hash,
            signature=signature,
            timestamp=timestamp,
            state_root=new_state_root,
            merkle_root=merkle_root,
            transactions=[tx_record],
        )
        block.hash = block.compute_hash()
        return block

    def append_block(self, block):
        """Commit block to ledger, apply transactions to World State atomically, and prune mempool."""
        staged_state = self.world_state.clone()
        staged_chaincode = ChaincodeEngine(
            self.config.get("personnel_registry", []),
            self.config.get("officials", {}).keys(),
            official_public_keys=self.official_public_keys,
        )
        staged_chaincode.world_state = staged_state

        if block.transactions:
            for tx in block.transactions:
                tx_record = cu.decrypt_payload(self.facility_key, tx["encrypted_payload"])
                tx_data = {
                    "employee_id": tx_record["employee_id"],
                    "timestamp": tx_record.get("timestamp", tx["timestamp"]),
                }
                if "extra" in tx_record:
                    tx_data.update(tx_record["extra"])
                if tx.get("tx_id"):
                    tx_data["tx_id"] = tx["tx_id"]
                staged_chaincode.execute_transaction(staged_state, tx_record["action"], tx_data, tx["official_id"])

        elif block.encrypted_payload != "GENESIS":
            record = self.decrypt_record(block)
            tx_data = {
                "employee_id": record["employee_id"],
                "timestamp": record.get("timestamp", block.timestamp),
            }
            if "extra" in record:
                tx_data.update(record["extra"])
            staged_chaincode.execute_transaction(staged_state, record["action"], tx_data, block.official_id)

        # Write to disk WAL FIRST before updating in-memory state (ensures crash-safety)
        self._persist_block(block)

        # Atomic commit to active blockchain and world state
        self.world_state = staged_state
        self.chaincode.world_state = staged_state
        self.chain.append(block)

        # Prune mempool
        if block.transactions:
            committed_ids = {t.get("tx_id") for t in block.transactions}
            self.mempool = [m for m in self.mempool if m.get("tx_id") not in committed_ids]
        else:
            self.mempool = [m for m in self.mempool if not (m["employee_id"] == block.official_id and m["timestamp"] == block.timestamp)]

        # Secondary mempool prune: filter out transactions that are now invalid against new state
        pruned_mempool = []
        temp_mem_state = self.world_state.clone()
        for pending in self.mempool:
            p_data = {"employee_id": pending["employee_id"], "timestamp": pending["timestamp"]}
            if pending.get("extra"):
                p_data.update(pending["extra"])
            try:
                staged_chaincode.execute_transaction(temp_mem_state, pending["action"], p_data, pending["official_id"])
                pruned_mempool.append(pending)
            except Exception:
                pass
        self.mempool = pruned_mempool

    # ── Path 2: Receive Block from Peer ──────────────────────────────────────

    def validate_incoming_block(self, block):
        """
        Independently re-validate a block received from a peer:
          1. Index continuity
          2. previous_hash linkage
          3. BLAKE3 block hash self-consistency
          4. Proposer authorization & Ed448 header signature
          5. BLAKE3 Merkle Tree Root verification over transactions
          6. Metadata consistency vs decrypted signed payload
          7. Payload decryptability & Ed448 signature verification per tx
          8. Chaincode execution + State Root commitment verification
        """
        last_block = self.chain[-1]

        if block.index != last_block.index + 1:
            raise ValueError(f"expected index {last_block.index + 1}, got {block.index}")
        if block.previous_hash != last_block.hash:
            raise ValueError("previous_hash does not match this node's chain tip")
        if block.hash != block.compute_hash():
            raise ValueError("block hash does not match its own contents")

        # Verify block proposer and header authenticity under PoA (Fixes Finding B)
        if not self._verify_block_proposer_and_signature(block, self.world_state):
            raise ValueError(f"Block proposer '{block.official_id}' or block signature invalid under PoA consensus")

        # Verify Merkle Root if transactions present
        if block.transactions:
            computed_merkle_root = MerkleTree(block.transactions).root
            if block.merkle_root != computed_merkle_root:
                raise ValueError(
                    f"Merkle root mismatch: block header has {block.merkle_root[:16]}..., "
                    f"computed {computed_merkle_root[:16]}..."
                )

            temp_state = self.world_state.clone()
            for tx in block.transactions:
                try:
                    record = cu.decrypt_payload(self.facility_key, tx["encrypted_payload"])
                except Exception:
                    raise ValueError("transaction payload does not decrypt with facility key")

                # Verify metadata consistency (Fixes Finding C)
                if not self._verify_tx_metadata_consistency(tx, record):
                    raise ValueError("Transaction visible metadata contradicts signed decrypted payload")

                tx_bytes = self._tx_bytes(
                    record["employee_id"], record["action"],
                    tx["official_id"], record["timestamp"],
                    extra_data=record.get("extra"),
                )
                official_key = self.official_public_keys.get(tx["official_id"])
                if not official_key or not cu.verify_signature(
                    official_key, tx_bytes, tx["signature"]
                ):
                    raise ValueError(f"Ed448 signature invalid for tx by {tx['official_id']}")

                tx_data = {
                    "employee_id": record["employee_id"],
                    "timestamp": record.get("timestamp", tx["timestamp"]),
                }
                if "extra" in record:
                    tx_data.update(record["extra"])
                if tx.get("tx_id"):
                    tx_data["tx_id"] = tx["tx_id"]
                self.chaincode.execute_transaction(temp_state, record["action"], tx_data, tx["official_id"])

            if not block.state_root or block.state_root != temp_state.compute_state_root():
                raise ValueError("State root mismatch on multi-transaction block replay")

            return block.transactions[0]

        else:
            # Single transaction block
            try:
                record = self.decrypt_record(block)
            except Exception:
                raise ValueError("payload does not decrypt with shared facility key")

            tx_bytes = self._tx_bytes(
                record["employee_id"], record["action"],
                block.official_id, record["timestamp"],
                extra_data=record.get("extra"),
            )
            official_key = self.official_public_keys.get(block.official_id)
            if not official_key or not cu.verify_signature(
                official_key, tx_bytes, block.signature
            ):
                raise ValueError("Ed448 signature does not verify against official's public key")

            tx_data = {
                "employee_id": record["employee_id"],
                "timestamp": record.get("timestamp", block.timestamp),
            }
            if "extra" in record:
                tx_data.update(record["extra"])

            temp_state = self.world_state.clone()
            expected_state_root = self.chaincode.execute_transaction(
                temp_state, record["action"], tx_data, block.official_id
            )

            if not block.state_root or block.state_root != expected_state_root:
                raise ValueError("State root mismatch on block replay")

            return record

    # ── Full self-check ───────────────────────────────────────────────────────

    def is_chain_valid(self):
        """
        Walk the chain and independently verify:
          1. Consecutive block indices (block.index == i)
          2. BLAKE3 block hashes & previous_hash continuity
          3. PoA block proposer authorization & Ed448 header signatures (Finding B)
          4. BLAKE3 binary Merkle roots over transactions
          5. Transaction metadata consistency vs decrypted signed payloads (Finding C)
          6. Sequential Chaincode state transitions & committed State Roots
          7. Live World State integrity vs ledger replayed state (Finding A)
        """
        results = []
        replay_chaincode = ChaincodeEngine(
            self.config.get("personnel_registry", []),
            self.config.get("officials", {}).keys(),
            official_public_keys=self.official_public_keys,
        )
        replay_state = replay_chaincode.world_state
        expected_genesis_root = replay_state.compute_state_root()

        for i, block in enumerate(self.chain):
            if i == 0:
                genesis_hash_ok = (
                    block.index == 0
                    and block.previous_hash == "0"
                    and block.hash == block.compute_hash()
                )
                genesis_state_ok = (block.state_root == expected_genesis_root)
                genesis_merkle_ok = (block.merkle_root == MerkleTree(["GENESIS"]).root)
                ok = genesis_hash_ok and genesis_state_ok and genesis_merkle_ok
                results.append(
                    {
                        "index": 0,
                        "hash_ok": genesis_hash_ok,
                        "signature_ok": True,
                        "contract_ok": True,
                        "state_root_ok": genesis_state_ok,
                        "merkle_root_ok": genesis_merkle_ok,
                        "valid": ok,
                    }
                )
                continue

            prev = self.chain[i - 1]
            index_ok = (block.index == i)
            hash_ok = (
                index_ok
                and block.hash == block.compute_hash()
                and block.previous_hash == prev.hash
            )

            # Check Merkle root
            merkle_ok = True
            if block.transactions:
                merkle_ok = (block.merkle_root == MerkleTree(block.transactions).root)

            # Block proposer and header authenticity under PoA (Fixes Finding B)
            proposer_sig_ok = self._verify_block_proposer_and_signature(block, replay_state)

            signature_ok = proposer_sig_ok
            contract_ok = True
            state_root_ok = True

            if block.transactions:
                for tx in block.transactions:
                    try:
                        record = cu.decrypt_payload(self.facility_key, tx["encrypted_payload"])

                        # Verify transaction metadata matches decrypted signed payload (Fixes Finding C)
                        if not self._verify_tx_metadata_consistency(tx, record):
                            signature_ok = False
                            contract_ok = False

                        tx_bytes = self._tx_bytes(
                            record["employee_id"], record["action"],
                            tx["official_id"], record["timestamp"],
                            extra_data=record.get("extra"),
                        )
                        off_key = self.official_public_keys.get(tx["official_id"])
                        if not off_key or not cu.verify_signature(off_key, tx_bytes, tx["signature"]):
                            signature_ok = False
                        tx_data = {
                            "employee_id": record["employee_id"],
                            "timestamp": record.get("timestamp", tx["timestamp"]),
                        }
                        if "extra" in record:
                            tx_data.update(record["extra"])
                        if tx.get("tx_id"):
                            tx_data["tx_id"] = tx["tx_id"]
                        replay_chaincode.execute_transaction(replay_state, record["action"], tx_data, tx["official_id"])
                    except Exception:
                        contract_ok = False
                        signature_ok = False
                state_root_ok = bool(block.state_root) and (block.state_root == replay_state.compute_state_root())
            else:
                try:
                    record = self.decrypt_record(block)
                    tx_bytes = self._tx_bytes(
                        record["employee_id"], record["action"],
                        block.official_id, record["timestamp"],
                        extra_data=record.get("extra"),
                    )
                    off_key = self.official_public_keys.get(block.official_id)
                    sig_valid = bool(off_key) and cu.verify_signature(off_key, tx_bytes, block.signature)
                    if not sig_valid:
                        signature_ok = False
                    tx_data = {
                        "employee_id": record["employee_id"],
                        "timestamp": record.get("timestamp", block.timestamp),
                    }
                    if "extra" in record:
                        tx_data.update(record["extra"])
                    new_root = replay_chaincode.execute_transaction(replay_state, record["action"], tx_data, block.official_id)
                    state_root_ok = bool(block.state_root) and (block.state_root == new_root)
                except Exception:
                    contract_ok = False
                    signature_ok = False
                    state_root_ok = False

            results.append(
                {
                    "index": block.index,
                    "hash_ok": hash_ok,
                    "signature_ok": signature_ok,
                    "contract_ok": contract_ok,
                    "state_root_ok": state_root_ok,
                    "merkle_root_ok": merkle_ok,
                    "valid": hash_ok and signature_ok and contract_ok and state_root_ok and merkle_ok,
                }
            )

        # LIVE STATE REPLAY COMPARISON (Fixes Finding A)
        # Compare live WorldState against independently replayed ledger state and latest committed block
        if results:
            live_state_root = self.world_state.compute_state_root()
            replayed_state_root = replay_state.compute_state_root()
            tip_block_root = self.chain[-1].state_root if self.chain else None

            live_matches = (live_state_root == replayed_state_root and live_state_root == tip_block_root)
            if not live_matches:
                results[-1]["live_state_ok"] = False
                results[-1]["state_root_ok"] = False
                results[-1]["valid"] = False
                results[-1]["error"] = (
                    f"Live World State divergence: live root '{live_state_root[:16]}...' "
                    f"does not match ledger replayed root '{replayed_state_root[:16]}...'"
                )

        return results

    # ── Longest-valid-chain adoption ──────────────────────────────────────────

    def replace_chain(self, new_chain_blocks):
        """Adopt new_chain_blocks if longer (or healing invalid local) and fully valid."""
        local_healthy = all(b["valid"] for b in self.is_chain_valid())
        if local_healthy and len(new_chain_blocks) <= len(self.chain):
            raise ValueError(f"rejected chain: candidate length ({len(new_chain_blocks)}) is not longer than current length ({len(self.chain)})")

        if not new_chain_blocks:
            raise ValueError("rejected chain: candidate chain is empty")

        if new_chain_blocks[0].hash != self.chain[0].hash:
            raise ValueError("rejected chain: genesis block does not match local genesis")

        replay_chaincode = ChaincodeEngine(
            self.config.get("personnel_registry", []),
            self.config.get("officials", {}).keys(),
            official_public_keys=self.official_public_keys,
        )
        replay_state = replay_chaincode.world_state

        for i, block in enumerate(new_chain_blocks):
            if block.index != i:
                raise ValueError(f"non-consecutive block index {block.index} at position {i}")

            if i == 0:
                if block.hash != block.compute_hash():
                    raise ValueError("invalid genesis block")
                continue

            prev = new_chain_blocks[i - 1]
            if block.hash != block.compute_hash() or block.previous_hash != prev.hash:
                raise ValueError(f"broken hash chain at block {block.index}")

            # Verify block proposer and header authenticity under PoA (Fixes Finding B)
            if not self._verify_block_proposer_and_signature(block, replay_state):
                raise ValueError(f"invalid block proposer or signature at block {block.index}")

            if block.transactions:
                if block.merkle_root != MerkleTree(block.transactions).root:
                    raise ValueError(f"invalid Merkle root at block {block.index}")
                for tx in block.transactions:
                    record = cu.decrypt_payload(self.facility_key, tx["encrypted_payload"])

                    # Verify metadata consistency (Fixes Finding C)
                    if not self._verify_tx_metadata_consistency(tx, record):
                        raise ValueError(f"metadata contradiction at block {block.index}")

                    tx_bytes = self._tx_bytes(
                        record["employee_id"], record["action"],
                        tx["official_id"], record["timestamp"],
                        extra_data=record.get("extra"),
                    )
                    off_key = self.official_public_keys.get(tx["official_id"])
                    if not off_key or not cu.verify_signature(off_key, tx_bytes, tx["signature"]):
                        raise ValueError(f"invalid Ed448 signature at block {block.index}")
                    tx_data = {
                        "employee_id": record["employee_id"],
                        "timestamp": record.get("timestamp", tx["timestamp"]),
                    }
                    if "extra" in record:
                        tx_data.update(record["extra"])
                    if tx.get("tx_id"):
                        tx_data["tx_id"] = tx["tx_id"]
                    replay_chaincode.execute_transaction(replay_state, record["action"], tx_data, tx["official_id"])
                if not block.state_root or block.state_root != replay_state.compute_state_root():
                    raise ValueError(f"state root mismatch at block {block.index}")
            else:
                record = self.decrypt_record(block)
                tx_bytes = self._tx_bytes(
                    record["employee_id"], record["action"],
                    block.official_id, record["timestamp"],
                    extra_data=record.get("extra"),
                )
                off_key = self.official_public_keys.get(block.official_id)
                if not off_key or not cu.verify_signature(off_key, tx_bytes, block.signature):
                    raise ValueError(f"invalid signature at block {block.index}")
                tx_data = {
                    "employee_id": record["employee_id"],
                    "timestamp": record.get("timestamp", block.timestamp),
                }
                if "extra" in record:
                    tx_data.update(record["extra"])
                new_root = replay_chaincode.execute_transaction(replay_state, record["action"], tx_data, block.official_id)
                if not block.state_root or block.state_root != new_root:
                    raise ValueError(f"state root mismatch at block {block.index}")

        self.chain = new_chain_blocks
        self.chaincode = replay_chaincode
        self.world_state = replay_state
        self._rewrite_storage()
