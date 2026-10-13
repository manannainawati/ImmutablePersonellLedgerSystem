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
        # Recompute merkle tree and block hash to fool naive hash checks
        from merkle_tree import MerkleTree
        tampered_block.merkle_root = MerkleTree(tampered_block.transactions).root
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

if __name__ == "__main__":
    unittest.main()
