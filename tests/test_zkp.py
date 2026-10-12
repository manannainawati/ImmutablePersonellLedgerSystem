"""
tests/test_zkp.py — Unit Tests for Zero-Knowledge Proof (ZKP) Range Compliance Primitives.
"""

import unittest
import time
import zkp_utils

class TestZeroKnowledgeProofs(unittest.TestCase):
    def test_pedersen_commitment(self):
        """Test Pedersen commitment generation and verification."""
        v = 28800  # 8 hours in seconds
        C, r = zkp_utils.pedersen_commit(v)
        self.assertTrue(zkp_utils.verify_commitment(C, v, r))

        # Different value or blinding must not verify
        self.assertFalse(zkp_utils.verify_commitment(C, v + 1, r))
        self.assertFalse(zkp_utils.verify_commitment(C, v, r + 1))

    def test_proof_of_knowledge_opening(self):
        """Test Schnorr-style Fiat-Shamir proof of knowledge."""
        v = 15000
        C, r = zkp_utils.pedersen_commit(v)
        proof = zkp_utils.prove_knowledge_of_opening(v, r, C, context="TEST")
        self.assertTrue(zkp_utils.verify_knowledge_of_opening(proof))

        # Tampered proof must fail
        tampered = dict(proof)
        tampered["z_v"] = hex(int(proof["z_v"], 16) + 1)
        self.assertFalse(zkp_utils.verify_knowledge_of_opening(tampered))

    def test_compliance_range_proof_valid(self):
        """Test valid zero-knowledge range proof for shift compliance."""
        # 8.5 hours worked (30,600 seconds), threshold is 8.0 hours (28,800 seconds)
        actual_worked = 30600
        threshold = 28800

        t0 = time.time()
        proof = zkp_utils.generate_compliance_proof(
            secret_value=actual_worked,
            threshold=threshold,
            employee_id="EMP1001",
            claim_type="MIN_SHIFT_HOURS"
        )
        gen_time = time.time() - t0

        t1 = time.time()
        valid, msg = zkp_utils.verify_compliance_proof(proof)
        verify_time = time.time() - t1

        self.assertTrue(valid, f"Proof should be valid: {msg}")
        self.assertIn("VERIFIED", msg)
        self.assertLess(gen_time, 2.5, f"Proof generation took {gen_time:.3f}s, expected < 2.5s")
        self.assertLess(verify_time, 2.5, f"Proof verification took {verify_time:.3f}s, expected < 2.5s")

    def test_compliance_range_proof_exact_threshold(self):
        """Test exact boundary condition: secret_value == threshold (Delta == 0)."""
        actual_worked = 28800
        threshold = 28800

        proof = zkp_utils.generate_compliance_proof(
            secret_value=actual_worked,
            threshold=threshold,
            employee_id="EMP1002",
            claim_type="MIN_SHIFT_HOURS"
        )
        valid, msg = zkp_utils.verify_compliance_proof(proof)
        self.assertTrue(valid, f"Boundary proof should be valid: {msg}")

    def test_compliance_range_proof_under_threshold_rejected(self):
        """Test that prover cannot generate proof when under threshold."""
        actual_worked = 25000  # < 28800
        threshold = 28800

        with self.assertRaises(ValueError):
            zkp_utils.generate_compliance_proof(
                secret_value=actual_worked,
                threshold=threshold,
                employee_id="EMP1003",
                claim_type="MIN_SHIFT_HOURS"
            )

    def test_tampered_proof_rejected(self):
        """Test that modifying proof payload or claim is caught and rejected."""
        actual_worked = 30000
        threshold = 28800

        proof = zkp_utils.generate_compliance_proof(
            secret_value=actual_worked,
            threshold=threshold,
            employee_id="EMP1001",
        )

        # 1. Modify threshold claim
        tampered_threshold = dict(proof)
        tampered_threshold["threshold"] = 35000  # Try to claim 35,000 threshold
        valid, msg = zkp_utils.verify_compliance_proof(tampered_threshold)
        self.assertFalse(valid, "Tampered threshold must be rejected by seal check")

        # 2. Modify bit commitment
        tampered_bits = dict(proof)
        new_commitments = list(proof["bit_commitments"])
        new_commitments[0] = hex(int(new_commitments[0], 16) + 1)
        tampered_bits["bit_commitments"] = new_commitments
        tampered_bits.pop("proof_seal", None)  # Even without seal
        valid, msg = zkp_utils.verify_compliance_proof(tampered_bits)
        self.assertFalse(valid, "Tampered bit commitment must fail mathematical verification")


    def test_zkp_api_routes(self):
        """Test Flask API endpoints /zkp/generate_proof and /zkp/verify_proof."""
        import node
        client = node.app.test_client()

        # 1. Generate proof for EMP1001 with simulated 8.5 hours
        res = client.post("/zkp/generate_proof", json={
            "employee_id": "EMP1001",
            "threshold_hours": 8.0,
            "simulated_hours": 8.5
        })
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data["success"])
        self.assertIn("proof", data)

        proof = data["proof"]
        self.assertEqual(proof["employee_id"], "EMP1001")
        self.assertEqual(proof["threshold_hours"], 8.0)

        # 2. Verify proof via API
        res_v = client.post("/zkp/verify_proof", json={"proof": proof})
        self.assertEqual(res_v.status_code, 200)
        data_v = res_v.get_json()
        self.assertTrue(data_v["valid"])

        # 3. Test API rejection for unmet threshold
        res_fail = client.post("/zkp/generate_proof", json={
            "employee_id": "EMP1001",
            "threshold_hours": 12.0,
            "simulated_hours": 8.0  # 8h < 12h
        })
        self.assertEqual(res_fail.status_code, 400)


if __name__ == "__main__":
    unittest.main()
