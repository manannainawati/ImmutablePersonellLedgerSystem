"""
tests/test_chaincode.py — Enterprise Chaincode Engine and Governance test suite:
  - World State transitions
  - Sequential check-in / check-out rules
  - Shift duration tracking
  - Onboarding (REGISTER_EMPLOYEE)
  - Key Revocation (REVOKE_OFFICIAL)
  - 2-of-N Multi-Signature Overrides (ADMIN_OVERRIDE)
"""
import unittest
import time
import json
from contract import ChaincodeEngine, ContractViolation
import crypto_utils as cu

class TestChaincode(unittest.TestCase):
    def setUp(self):
        with open("network_config.json") as f:
            self.config = json.load(f)
        self.engine = ChaincodeEngine(
            self.config["personnel_registry"],
            self.config["officials"].keys()
        )
        self.state = self.engine.world_state

        with open("keys/OFFICIAL_A.key") as f:
            self.priv_A = cu.private_key_from_str(f.read().strip())
        with open("keys/OFFICIAL_B.key") as f:
            self.priv_B = cu.private_key_from_str(f.read().strip())

    def test_valid_attendance_cycle(self):
        t1 = 1000.0
        self.engine.execute_transaction(self.state, "CHECK_IN", {"employee_id": "EMP1001", "timestamp": t1}, "OFFICIAL_A")
        self.assertEqual(self.state.get_employee("EMP1001")["status"], "IN")

        t2 = t1 + 3600.0  # 1 hour later
        self.engine.execute_transaction(self.state, "CHECK_OUT", {"employee_id": "EMP1001", "timestamp": t2}, "OFFICIAL_A")
        emp = self.state.get_employee("EMP1001")
        self.assertEqual(emp["status"], "OUT")
        self.assertEqual(emp["total_seconds_worked"], 3600.0)

    def test_double_checkin_rejected(self):
        t1 = 1000.0
        self.engine.execute_transaction(self.state, "CHECK_IN", {"employee_id": "EMP1001", "timestamp": t1}, "OFFICIAL_A")
        with self.assertRaises(ContractViolation):
            self.engine.execute_transaction(self.state, "CHECK_IN", {"employee_id": "EMP1001", "timestamp": t1 + 10}, "OFFICIAL_A")

    def test_unregistered_employee_rejected(self):
        with self.assertRaises(ContractViolation):
            self.engine.execute_transaction(self.state, "CHECK_IN", {"employee_id": "EMP9999", "timestamp": 1000.0}, "OFFICIAL_A")

    def test_onboarding_employee(self):
        self.assertFalse(self.state.is_employee_registered("EMP3000"))
        self.engine.execute_transaction(
            self.state, "REGISTER_EMPLOYEE",
            {"employee_id": "EMP3000", "department": "Operations", "timestamp": 1000.0},
            "OFFICIAL_A"
        )
        self.assertTrue(self.state.is_employee_registered("EMP3000"))
        # Newly onboarded employee can check in
        self.engine.execute_transaction(self.state, "CHECK_IN", {"employee_id": "EMP3000", "timestamp": 1005.0}, "OFFICIAL_A")
        self.assertEqual(self.state.get_employee("EMP3000")["status"], "IN")

    def test_revocation_of_official(self):
        self.assertTrue(self.state.is_official_active("OFFICIAL_B"))
        self.engine.execute_transaction(
            self.state, "REVOKE_OFFICIAL",
            {"target_official": "OFFICIAL_B", "timestamp": 1000.0},
            "OFFICIAL_A"
        )
        self.assertFalse(self.state.is_official_active("OFFICIAL_B"))

        # Transactions signed by revoked official must be rejected
        with self.assertRaises(ContractViolation):
            self.engine.execute_transaction(self.state, "CHECK_IN", {"employee_id": "EMP1002", "timestamp": 1010.0}, "OFFICIAL_B")

    def test_multisig_override(self):
        t = 2000.0
        # Single official override MUST be rejected
        with self.assertRaises(ContractViolation):
            self.engine.execute_transaction(
                self.state, "ADMIN_OVERRIDE",
                {"employee_id": "EMP1001", "override_status": "IN", "timestamp": t},
                "OFFICIAL_A"
            )

        # 2-of-N co-signed override succeeds
        co_bytes = ChaincodeEngine.compute_override_co_sign_bytes(
            "EMP1001", "IN", "OFFICIAL_A", "OFFICIAL_B", t
        )
        co_sig = cu.sign_bytes(self.priv_B, co_bytes)

        self.engine.execute_transaction(
            self.state, "ADMIN_OVERRIDE",
            {
                "employee_id": "EMP1001",
                "override_status": "IN",
                "co_official_id": "OFFICIAL_B",
                "co_signature": co_sig,
                "timestamp": t,
            },
            "OFFICIAL_A"
        )
        self.assertEqual(self.state.get_employee("EMP1001")["status"], "IN")

if __name__ == "__main__":
    unittest.main()
