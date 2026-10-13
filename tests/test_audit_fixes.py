"""
tests/test_audit_fixes.py — Regression tests for Audit Findings A, B, C, D, and E:
  - Finding A: Live state tampering is detected by is_chain_valid()
  - Finding B: Block proposer identity and block-level header signatures are enforced
  - Finding C: Transaction metadata contradictions with encrypted payload are rejected
  - Finding D: Old attendance transactions cannot be replayed (tx_id & timestamp monotonicity)
  - Finding E: Non-finite (NaN, Inf) and invalid timestamps are strictly rejected
"""
import unittest
import json
import time
import math
import copy
from blockchain import Blockchain, Block
from contract import ChaincodeEngine, ContractViolation
import crypto_utils as cu

class TestAuditFixes(unittest.TestCase):
    def setUp(self):
        with open("network_config.json") as f:
            self.config = json.load(f)

        with open("keys/OFFICIAL_A.key") as f:
            self.priv_A = cu.private_key_from_str(f.read().strip())
        with open("keys/OFFICIAL_B.key") as f:
            self.priv_B = cu.private_key_from_str(f.read().strip())

    # =========================================================================
    # Finding A: Live state tampering detection
    # =========================================================================
    def test_finding_a_live_state_tampering_detected(self):
        chain = Blockchain(self.config)
        t = time.time()
        tx_b = Blockchain._tx_bytes("EMP1001", "CHECK_IN", "OFFICIAL_A", t)
        sig = cu.sign_bytes(self.priv_A, tx_b)

        b1 = chain.build_block_from_transaction("EMP1001", "CHECK_IN", "OFFICIAL_A", t, sig)
        chain.append_block(b1)

        # Baseline: chain is valid
        val_before = chain.is_chain_valid()
        self.assertTrue(all(v["valid"] for v in val_before))

        # Attacker tampers directly with in-memory world_state
        chain.world_state.employees["EMP1001"]["total_seconds_worked"] = 99999.0

        # is_chain_valid() must catch the discrepancy between replayed state and live state
        val_after = chain.is_chain_valid()
        self.assertFalse(val_after[-1]["valid"], "Chain check should fail when live world_state is tampered")
        self.assertFalse(val_after[-1].get("live_state_ok", True), "live_state_ok flag should be False")

    # =========================================================================
    # Finding B: Block-level identity and signature verification
    # =========================================================================
    def test_finding_b_block_proposer_and_signature_verified(self):
        chain = Blockchain(self.config)
        t = time.time()

        for emp in ["EMP1001", "EMP1002"]:
            tx_b = Blockchain._tx_bytes(emp, "CHECK_IN", "OFFICIAL_A", t)
            sig = cu.sign_bytes(self.priv_A, tx_b)
            chain.add_to_mempool(emp, "CHECK_IN", "OFFICIAL_A", t, sig)

        block = chain.build_block_from_mempool(max_txs=10, proposer_id="OFFICIAL_A")
        self.assertIsNotNone(block)

        # Case 1: Tampered proposer official_id to ATTACKER
        forged_block = copy.deepcopy(block)
        forged_block.official_id = "ATTACKER"
        forged_block.hash = forged_block.compute_hash()

        with self.assertRaises(ValueError) as ctx:
            chain.validate_incoming_block(forged_block)
        self.assertIn("invalid under PoA consensus", str(ctx.exception))

        # Also verify is_chain_valid detects it if it were in the chain
        chain_with_forged = Blockchain(self.config)
        chain_with_forged.chain.append(forged_block)
        val = chain_with_forged.is_chain_valid()
        self.assertFalse(val[-1]["valid"], "Chain check must reject block with unregistered proposer")

        # Case 2: Tampered block signature with valid official_id
        forged_sig_block = copy.deepcopy(block)
        forged_sig_block.signature = "invalid_fake_signature_base64"
        forged_sig_block.hash = forged_sig_block.compute_hash()

        with self.assertRaises(ValueError) as ctx:
            chain.validate_incoming_block(forged_sig_block)
        self.assertIn("Block proposer", str(ctx.exception))

        chain_with_forged_sig = Blockchain(self.config)
        chain_with_forged_sig.chain.append(forged_sig_block)
        val = chain_with_forged_sig.is_chain_valid()
        self.assertFalse(val[-1]["valid"], "Chain check must reject block with invalid header signature")

    # =========================================================================
    # Finding C: Transaction metadata contradictions rejected
    # =========================================================================
    def test_finding_c_tx_metadata_contradiction_rejected(self):
        chain = Blockchain(self.config)
        t = time.time()
        tx_b = Blockchain._tx_bytes("EMP1001", "CHECK_IN", "OFFICIAL_A", t)
        sig = cu.sign_bytes(self.priv_A, tx_b)

        block = chain.build_block_from_transaction("EMP1001", "CHECK_IN", "OFFICIAL_A", t, sig)

        # Attacker modifies the visible employee_id to EMP1002
        tampered_block = copy.deepcopy(block)
        tampered_block.transactions[0]["employee_id"] = "EMP1002"
        # Recompute merkle tree and re-sign block header so header signature is valid
        from merkle_tree import MerkleTree
        tampered_block.merkle_root = MerkleTree(tampered_block.transactions).root
        header_bytes = chain._block_header_bytes(
            tampered_block.index, tampered_block.previous_hash,
            tampered_block.merkle_root, tampered_block.state_root,
            tampered_block.timestamp, tampered_block.official_id
        )
        tampered_block.signature = cu.sign_bytes(self.priv_A, header_bytes)
        tampered_block.hash = tampered_block.compute_hash()

        with self.assertRaises(ValueError) as ctx:
            chain.validate_incoming_block(tampered_block)
        self.assertIn("Transaction visible metadata contradicts signed decrypted payload", str(ctx.exception))

        # Also verify is_chain_valid rejects it
        chain_with_tampered = Blockchain(self.config)
        chain_with_tampered.chain.append(tampered_block)
        val = chain_with_tampered.is_chain_valid()
        self.assertFalse(val[-1]["valid"], "Chain check must reject block with metadata contradictions")

    # =========================================================================
    # Finding D: Replay attack prevention & Monotonic timestamps
    # =========================================================================
    def test_finding_d_replay_attack_prevention(self):
        engine = ChaincodeEngine(
            self.config["personnel_registry"],
            self.config["officials"].keys()
        )
        state = engine.world_state

        t1 = 1000.0
        tx1_id = "TX-IN-001"
        engine.execute_transaction(
            state, "CHECK_IN",
            {"employee_id": "EMP1001", "timestamp": t1, "tx_id": tx1_id},
            "OFFICIAL_A"
        )
        self.assertEqual(state.get_employee("EMP1001")["status"], "IN")

        t2 = 4600.0  # 1 hour later
        tx2_id = "TX-OUT-001"
        engine.execute_transaction(
            state, "CHECK_OUT",
            {"employee_id": "EMP1001", "timestamp": t2, "tx_id": tx2_id},
            "OFFICIAL_A"
        )
        self.assertEqual(state.get_employee("EMP1001")["status"], "OUT")
        self.assertEqual(state.get_employee("EMP1001")["total_seconds_worked"], 3600.0)

        # Attempt 1: Replay exact same transaction (same tx_id)
        with self.assertRaises(ContractViolation) as ctx:
            engine.execute_transaction(
                state, "CHECK_IN",
                {"employee_id": "EMP1001", "timestamp": t1, "tx_id": tx1_id},
                "OFFICIAL_A"
            )
        self.assertIn("already been executed", str(ctx.exception))

        # Attempt 2: Replay with old timestamp t1 using a fresh tx_id
        with self.assertRaises(ContractViolation) as ctx:
            engine.execute_transaction(
                state, "CHECK_IN",
                {"employee_id": "EMP1001", "timestamp": t1, "tx_id": "TX-IN-REPLAY"},
                "OFFICIAL_A"
            )
        self.assertIn("must be strictly greater than last action timestamp", str(ctx.exception))

        # Verify state total worked was NOT inflated
        self.assertEqual(state.get_employee("EMP1001")["total_seconds_worked"], 3600.0)

    # =========================================================================
    # Finding E: Non-finite timestamps strictly rejected
    # =========================================================================
    def test_finding_e_non_finite_timestamps_rejected(self):
        engine = ChaincodeEngine(
            self.config["personnel_registry"],
            self.config["officials"].keys()
        )
        state = engine.world_state

        bad_timestamps = [
            float("nan"),
            float("inf"),
            float("-inf"),
            -1.0,
            0.0,
            True,        # bool is an instance of int in Python
            False,
            1e15,        # far future unreasonable timestamp
            "1000",      # string
            None
        ]

        for bad_ts in bad_timestamps:
            with self.subTest(bad_ts=bad_ts):
                with self.assertRaises(ContractViolation):
                    engine.execute_transaction(
                        state, "CHECK_IN",
                        {"employee_id": "EMP1001", "timestamp": bad_ts},
                        "OFFICIAL_A"
                    )

    # =========================================================================
    # Certificate Verifier Control-Flow & Fraud Prevention
    # =========================================================================
    def test_certificate_verifier_rejects_fraudulent_claims(self):
        from verify_certificate import verify_certificate_dict
        import hash_utils

        # Case 1: Certificate claiming hours worked but with empty audit events
        fraud_cert_empty_events = {
            "certificate_id": "CERT-FRAUD-001",
            "standard": "ISO-27001",
            "employee_id": "EMP1001",
            "department": "Engineering",
            "total_hours_worked": 40.0,
            "current_status": "OUT",
            "on_chain_events_count": 0,
            "audit_events": [],
        }
        # Seal it
        seal = hash_utils.compute_block_hash(json.dumps(fraud_cert_empty_events, sort_keys=True).encode())
        fraud_cert_empty_events["cryptographic_seal"] = seal

        self.assertFalse(verify_certificate_dict(fraud_cert_empty_events, self.config))

        # Case 2: Certificate with bogus signature on event
        fraud_cert_bad_sig = {
            "certificate_id": "CERT-FRAUD-002",
            "standard": "ISO-27001",
            "employee_id": "EMP1001",
            "department": "Engineering",
            "total_hours_worked": 1.0,
            "current_status": "OUT",
            "on_chain_events_count": 1,
            "audit_events": [
                {
                    "block_index": 1,
                    "action": "CHECK_IN",
                    "timestamp": 1000.0,
                    "official_id": "OFFICIAL_A",
                    "ed448_signature": "bogus_signature_bytes_base64",
                    "merkle_root": "0" * 64,
                }
            ],
        }
        seal = hash_utils.compute_block_hash(json.dumps(fraud_cert_bad_sig, sort_keys=True).encode())
        fraud_cert_bad_sig["cryptographic_seal"] = seal

        self.assertFalse(verify_certificate_dict(fraud_cert_bad_sig, self.config))

        # Case 3: Certificate with invalid / nonsensical Merkle proof
        fraud_cert_bad_merkle = {
            "certificate_id": "CERT-FRAUD-003",
            "standard": "ISO-27001",
            "employee_id": "EMP1001",
            "department": "Engineering",
            "total_hours_worked": 1.0,
            "current_status": "OUT",
            "on_chain_events_count": 1,
            "audit_events": [
                {
                    "block_index": 1,
                    "action": "CHECK_IN",
                    "timestamp": 1000.0,
                    "official_id": "OFFICIAL_A",
                    "ed448_signature": cu.sign_bytes(
                        self.priv_A,
                        Blockchain._tx_bytes("EMP1001", "CHECK_IN", "OFFICIAL_A", 1000.0)
                    ),
                    "merkle_root": "abcdef1234567890" * 4,
                    "spv_merkle_proof": [{"position": "left", "hash": "0" * 64}],
                }
            ],
        }
        seal = hash_utils.compute_block_hash(json.dumps(fraud_cert_bad_merkle, sort_keys=True).encode())
        fraud_cert_bad_merkle["cryptographic_seal"] = seal

        self.assertFalse(verify_certificate_dict(fraud_cert_bad_merkle, self.config))

    # =========================================================================
    # Fix 1 Regression: Block timestamp tampering detected
    # =========================================================================
    def test_block_timestamp_tampering_rejected(self):
        chain = Blockchain(self.config)
        t = 1000.0
        tx_b = Blockchain._tx_bytes("EMP1001", "CHECK_IN", "OFFICIAL_A", t)
        sig = cu.sign_bytes(self.priv_A, tx_b)

        block = chain.build_block_from_transaction("EMP1001", "CHECK_IN", "OFFICIAL_A", t, sig)
        chain.append_block(block)

        # Baseline: chain is 100% valid
        val_before = chain.is_chain_valid()
        self.assertTrue(all(v["valid"] for v in val_before))

        # Attacker modifies block timestamp, recomputes block hash, leaves tx unchanged
        tampered_block = copy.deepcopy(block)
        tampered_block.timestamp = t + 500.0  # altered block timestamp
        tampered_block.hash = tampered_block.compute_hash()  # recomputed hash

        # 1. validate_incoming_block on a peer must reject the tampered block
        peer_chain = Blockchain(self.config)
        with self.assertRaises(ValueError) as ctx:
            peer_chain.validate_incoming_block(tampered_block)
        self.assertIn("invalid under PoA consensus", str(ctx.exception))

        # 2. is_chain_valid must report valid: False because header signature was invalidated
        chain_with_tampered = Blockchain(self.config)
        chain_with_tampered.chain.append(tampered_block)
        val = chain_with_tampered.is_chain_valid()
        self.assertFalse(val[-1]["valid"], "Block with altered timestamp must fail chain validation")
        self.assertFalse(val[-1]["signature_ok"], "Block header signature must fail when timestamp is altered")

    # =========================================================================
    # Fix 2 Regression: Forged audit certificates with arbitrary roots / missing proofs
    # =========================================================================
    def test_certificate_arbitrary_merkle_root_and_missing_proof_rejected(self):
        from verify_certificate import verify_certificate_dict
        import hash_utils

        tx_bytes = Blockchain._tx_bytes("EMP1001", "CHECK_IN", "OFFICIAL_A", 1000.0)
        valid_tx_sig = cu.sign_bytes(self.priv_A, tx_bytes)

        # Sub-case A: Valid signed event, arbitrary Merkle root, NO inclusion proof (spv_proof = None)
        cert_no_proof = {
            "certificate_id": "CERT-FORGED-NO-PROOF",
            "standard": "ISO-27001",
            "issuer_id": "OFFICIAL_A",
            "employee_id": "EMP1001",
            "department": "Engineering",
            "total_hours_worked": 1.0,
            "current_status": "IN",
            "on_chain_events_count": 1,
            "audit_events": [{
                "block_index": 1,
                "action": "CHECK_IN",
                "timestamp": 1000.0,
                "official_id": "OFFICIAL_A",
                "ed448_signature": valid_tx_sig,
                "merkle_root": "a" * 64,  # Arbitrary Merkle root
                "spv_merkle_proof": None,  # Missing inclusion proof!
                "tx_leaf": None,
            }],
        }
        seal = hash_utils.compute_block_hash(json.dumps(cert_no_proof, sort_keys=True).encode())
        cert_no_proof["cryptographic_seal"] = seal
        cert_no_proof["issuer_signature"] = cu.sign_bytes(self.priv_A, seal.encode())
        self.assertFalse(verify_certificate_dict(cert_no_proof, self.config), "Must reject cert omitting inclusion proof")

        # Sub-case B: Valid signed event, arbitrary Merkle root, empty proof list []
        cert_empty_proof = copy.deepcopy(cert_no_proof)
        cert_empty_proof["certificate_id"] = "CERT-FORGED-EMPTY-PROOF"
        cert_empty_proof["audit_events"][0]["spv_merkle_proof"] = []
        cert_empty_proof["audit_events"][0]["tx_leaf"] = {"employee_id": "EMP1001", "action": "CHECK_IN", "timestamp": 1000.0}
        cert_empty_proof.pop("cryptographic_seal", None)
        cert_empty_proof.pop("issuer_signature", None)
        seal = hash_utils.compute_block_hash(json.dumps(cert_empty_proof, sort_keys=True).encode())
        cert_empty_proof["cryptographic_seal"] = seal
        cert_empty_proof["issuer_signature"] = cu.sign_bytes(self.priv_A, seal.encode())
        self.assertFalse(verify_certificate_dict(cert_empty_proof, self.config), "Must reject arbitrary root with empty proof")

        # Sub-case C: Forged issuer identity or invalid issuer signature
        cert_fake_issuer = copy.deepcopy(cert_no_proof)
        cert_fake_issuer["issuer_id"] = "UNAUTHORIZED_ATTACKER"
        cert_fake_issuer.pop("cryptographic_seal", None)
        cert_fake_issuer.pop("issuer_signature", None)
        seal = hash_utils.compute_block_hash(json.dumps(cert_fake_issuer, sort_keys=True).encode())
        cert_fake_issuer["cryptographic_seal"] = seal
        cert_fake_issuer["issuer_signature"] = cu.sign_bytes(self.priv_A, seal.encode())
        self.assertFalse(verify_certificate_dict(cert_fake_issuer, self.config), "Must reject unregistered certificate issuer")

    # =========================================================================
    # Fix 4 Regression: Restart Recovery from Disk WAL
    # =========================================================================
    def test_restart_recovery_from_wal(self):
        import os
        import shutil
        test_dir = "data/test_restart_wal"
        if os.path.exists(test_dir):
            shutil.rmtree(test_dir)
        os.makedirs(test_dir, exist_ok=True)
        wal_path = os.path.join(test_dir, "chain.jsonl")

        # Session 1: Create chain, execute check-in and check-out
        chain1 = Blockchain(self.config, storage_path=wal_path)
        t1 = 1000.0
        sig1 = cu.sign_bytes(self.priv_A, Blockchain._tx_bytes("EMP1001", "CHECK_IN", "OFFICIAL_A", t1))
        b1 = chain1.build_block_from_transaction("EMP1001", "CHECK_IN", "OFFICIAL_A", t1, sig1)
        chain1.append_block(b1)

        t2 = 4600.0
        sig2 = cu.sign_bytes(self.priv_A, Blockchain._tx_bytes("EMP1001", "CHECK_OUT", "OFFICIAL_A", t2))
        b2 = chain1.build_block_from_transaction("EMP1001", "CHECK_OUT", "OFFICIAL_A", t2, sig2)
        chain1.append_block(b2)

        self.assertEqual(len(chain1.chain), 3)
        self.assertEqual(chain1.world_state.get_employee("EMP1001")["status"], "OUT")
        self.assertEqual(chain1.world_state.get_employee("EMP1001")["total_seconds_worked"], 3600.0)

        # Session 2: Node restart — instantiate fresh Blockchain loading from wal_path
        chain2 = Blockchain(self.config, storage_path=wal_path)
        self.assertEqual(len(chain2.chain), 3)
        self.assertEqual(chain2.world_state.get_employee("EMP1001")["status"], "OUT")
        self.assertEqual(chain2.world_state.get_employee("EMP1001")["total_seconds_worked"], 3600.0)

        val = chain2.is_chain_valid()
        self.assertTrue(all(v["valid"] for v in val), "Replayed chain after restart must be 100% valid")

        # Cleanup
        shutil.rmtree(test_dir)

    # =========================================================================
    # Fix 4 Regression: Chain Replacement with Valid vs Tampered Chains
    # =========================================================================
    def test_chain_replacement_valid_and_tampered(self):
        # Local node has 1 block
        chain_local = Blockchain(self.config)
        t1 = 1000.0
        sig1 = cu.sign_bytes(self.priv_A, Blockchain._tx_bytes("EMP1001", "CHECK_IN", "OFFICIAL_A", t1))
        b1 = chain_local.build_block_from_transaction("EMP1001", "CHECK_IN", "OFFICIAL_A", t1, sig1)
        chain_local.append_block(b1)
        self.assertEqual(len(chain_local.chain), 2)

        # Peer node has longer valid chain (3 blocks)
        chain_peer = Blockchain(self.config)
        b1_peer = chain_peer.build_block_from_transaction("EMP1001", "CHECK_IN", "OFFICIAL_A", t1, sig1)
        chain_peer.append_block(b1_peer)
        t2 = 2000.0
        sig2 = cu.sign_bytes(self.priv_B, Blockchain._tx_bytes("EMP1002", "CHECK_IN", "OFFICIAL_B", t2))
        b2_peer = chain_peer.build_block_from_transaction("EMP1002", "CHECK_IN", "OFFICIAL_B", t2, sig2)
        chain_peer.append_block(b2_peer)
        self.assertEqual(len(chain_peer.chain), 3)

        # 1. Successful replacement by longer valid chain
        replaced = chain_local.replace_chain(chain_peer.chain)
        self.assertTrue(replaced)
        self.assertEqual(len(chain_local.chain), 3)
        self.assertEqual(chain_local.world_state.get_employee("EMP1002")["status"], "IN")

        # 2. Attempt replacement with a tampered chain (tampered header signature on block 2)
        chain_local_short = Blockchain(self.config)
        b1_short = chain_local_short.build_block_from_transaction("EMP1001", "CHECK_IN", "OFFICIAL_A", t1, sig1)
        chain_local_short.append_block(b1_short)
        self.assertEqual(len(chain_local_short.chain), 2)

        tampered_chain_blocks = copy.deepcopy(chain_peer.chain)
        tampered_chain_blocks[2].timestamp += 999.0
        tampered_chain_blocks[2].hash = tampered_chain_blocks[2].compute_hash()

        with self.assertRaises(ValueError) as ctx:
            chain_local_short.replace_chain(tampered_chain_blocks)
        self.assertIn("invalid block proposer or signature", str(ctx.exception))

    # =========================================================================
    # Fix 4 Regression: Multi-Transaction Blocks & Merkle Verification
    # =========================================================================
    def test_multi_transaction_block_mempool_packing_and_spv(self):
        from merkle_tree import MerkleTree
        chain = Blockchain(self.config)
        t = 1000.0

        for emp in ["EMP1001", "EMP1002", "EMP1003"]:
            tx_b = Blockchain._tx_bytes(emp, "CHECK_IN", "OFFICIAL_A", t)
            sig = cu.sign_bytes(self.priv_A, tx_b)
            chain.add_to_mempool(emp, "CHECK_IN", "OFFICIAL_A", t, sig)

        self.assertEqual(len(chain.mempool), 3)
        multi_block = chain.build_block_from_mempool(max_txs=10, proposer_id="OFFICIAL_A")
        self.assertIsNotNone(multi_block)
        self.assertEqual(len(multi_block.transactions), 3)

        # Incoming block validation
        chain.validate_incoming_block(multi_block)
        chain.append_block(multi_block)

        # Verify SPV Merkle inclusion proof for each transaction in the block
        tree = MerkleTree(multi_block.transactions)
        for tx_idx, tx in enumerate(multi_block.transactions):
            proof = tree.get_proof(tx_idx)
            self.assertTrue(MerkleTree.verify_proof(tx, proof, multi_block.merkle_root))

        # World state check
        for emp in ["EMP1001", "EMP1002", "EMP1003"]:
            self.assertEqual(chain.world_state.get_employee(emp)["status"], "IN")

        val = chain.is_chain_valid()
        self.assertTrue(all(v["valid"] for v in val), "Multi-transaction block must pass chain self-check")


if __name__ == "__main__":
    unittest.main()
