"""
tests/test_elite_features.py — Automated Unit & Integration Tests for:
  - Feature 1: Web Signing Portal & Employee Digital Badges
  - Feature 3: SOC-2 / ISO-27001 Cryptographic Audit Certificate & Offline Verifier
  - Feature 4: High-Throughput Mempool & TPS Benchmark Logic
"""

import unittest
import json
import os
import shutil
import time

import crypto_utils as cu
from blockchain import Blockchain
from verify_certificate import verify_certificate_dict
import hash_utils

class TestEliteFeatures(unittest.TestCase):
    def setUp(self):
        self.test_dir = "data/test_node_elite"
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

        with open("network_config.json") as f:
            self.config = json.load(f)

        self.storage_path = os.path.join(self.test_dir, "chain.jsonl")
        self.chain = Blockchain(self.config, storage_path=self.storage_path)

        with open("keys/OFFICIAL_A.key") as f:
            self.priv_A = cu.private_key_from_str(f.read().strip())

    def tearDown(self):
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

    def test_feature_1_digital_badge_and_state(self):
        """Feature 1: Test that employee state tracks properly for digital badge generation."""
        # 1. Register employee
        t0 = time.time()
        tx_b = Blockchain._tx_bytes("EMP9999", "REGISTER_EMPLOYEE", "OFFICIAL_A", t0)
        sig = cu.sign_bytes(self.priv_A, tx_b)
        block1 = self.chain.build_block_from_transaction(
            "EMP9999", "REGISTER_EMPLOYEE", "OFFICIAL_A", t0, sig, extra_data={"department": "Quantum Security"}
        )
        self.chain.append_block(block1)

        # 2. Check in
        t1 = t0 + 10
        tx_b = Blockchain._tx_bytes("EMP9999", "CHECK_IN", "OFFICIAL_A", t1)
        sig = cu.sign_bytes(self.priv_A, tx_b)
        block2 = self.chain.build_block_from_transaction("EMP9999", "CHECK_IN", "OFFICIAL_A", t1, sig)
        self.chain.append_block(block2)

        emp = self.chain.world_state.get_employee("EMP9999")
        self.assertIsNotNone(emp)
        self.assertEqual(emp["status"], "IN")
        self.assertEqual(emp["department"], "Quantum Security")

        # 3. Check out
        t2 = t1 + 3600 # 1 hour later
        tx_b = Blockchain._tx_bytes("EMP9999", "CHECK_OUT", "OFFICIAL_A", t2)
        sig = cu.sign_bytes(self.priv_A, tx_b)
        block3 = self.chain.build_block_from_transaction("EMP9999", "CHECK_OUT", "OFFICIAL_A", t2, sig)
        self.chain.append_block(block3)

        emp = self.chain.world_state.get_employee("EMP9999")
        self.assertEqual(emp["status"], "OUT")
        self.assertAlmostEqual(emp["total_seconds_worked"], 3600, delta=1)

    def test_feature_3_audit_certificate_and_offline_verifier(self):
        """Feature 3: Test certificate compilation, cryptographic sealing, and offline verification."""
        # Create history for EMP1001
        t0 = time.time()
        tx_b = Blockchain._tx_bytes("EMP1001", "CHECK_IN", "OFFICIAL_A", t0)
        sig = cu.sign_bytes(self.priv_A, tx_b)
        block = self.chain.build_block_from_transaction("EMP1001", "CHECK_IN", "OFFICIAL_A", t0, sig)
        self.chain.append_block(block)

        # Simulate /audit/certificate/EMP1001 payload construction
        audit_records = [{
            "block_index": block.index,
            "timestamp": block.timestamp,
            "action": "CHECK_IN",
            "official_id": block.official_id,
            "ed448_signature": block.signature,
            "block_hash": block.hash,
            "state_root": block.state_root,
            "merkle_root": block.merkle_root,
            "spv_merkle_proof": [],
        }]

        cert_data = {
            "certificate_id": f"CERT-IPLS-EMP1001-{int(t0)}",
            "standard": "ISO-27001 / SOC-2 Type II Digital Custody Audit",
            "issued_at": t0,
            "employee_id": "EMP1001",
            "department": "Engineering",
            "current_status": "IN",
            "total_seconds_worked": 0,
            "total_hours_worked": 0.0,
            "state_root_at_issuance": self.chain.world_state.compute_state_root(),
            "on_chain_events_count": len(audit_records),
            "audit_events": audit_records,
        }

        # Domain-keyed BLAKE3 seal
        cert_canonical_bytes = json.dumps(cert_data, sort_keys=True).encode()
        cert_data["cryptographic_seal"] = hash_utils.compute_block_hash(cert_canonical_bytes)

        # Run offline verification with standalone tool
        verified = verify_certificate_dict(cert_data, config=self.config)
        self.assertTrue(verified, "Cryptographic audit certificate must pass offline verification")

        # Tamper detection test
        tampered_cert = dict(cert_data)
        tampered_cert["department"] = "Tampered Fraud Department"
        self.assertFalse(
            verify_certificate_dict(tampered_cert, config=self.config),
            "Offline verifier must reject tampered certificate data"
        )

    def test_feature_4_high_throughput_mempool(self):
        """Feature 4: Test batch mempool ingestion and single-block multi-tx packing."""
        t_base = time.time()
        
        # Ingest check-ins for 3 registered employees
        tx_specs = [
            ("EMP1001", "CHECK_IN"),
            ("EMP1002", "CHECK_IN"),
            ("EMP1003", "CHECK_IN"),
        ]

        for i, (emp_id, action) in enumerate(tx_specs):
            t_tx = t_base + (i * 2)
            tx_b = Blockchain._tx_bytes(emp_id, action, "OFFICIAL_A", t_tx)
            sig = cu.sign_bytes(self.priv_A, tx_b)
            self.chain.add_to_mempool(emp_id, action, "OFFICIAL_A", t_tx, sig)

        self.assertEqual(len(self.chain.mempool), len(tx_specs))

        # Pack all into a single high-throughput block
        block = self.chain.build_block_from_mempool(max_txs=len(tx_specs), proposer_id="OFFICIAL_A")
        self.assertIsNotNone(block)
        self.assertEqual(len(block.transactions), len(tx_specs))
        self.assertIsNotNone(block.merkle_root)
        self.assertIsNotNone(block.state_root)

        self.chain.append_block(block)
        self.assertEqual(len(self.chain.mempool), 0, "Mempool should be cleared after packing")


if __name__ == "__main__":
    unittest.main()
