"""
demos/demo_governance.py — Demonstration of Enterprise Chaincode Governance.

Demonstrates:
  1. On-Chain Personnel Onboarding (REGISTER_EMPLOYEE)
  2. On-Chain Official Key Revocation CRL (REVOKE_OFFICIAL)
  3. 2-of-N Multi-Signature Emergency Overrides (ADMIN_OVERRIDE)

Usage:
    python demos/demo_governance.py
"""

import os
import sys
import json
import time

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from blockchain import Blockchain
from contract import ContractViolation
import crypto_utils as cu


def main():
    print("=" * 65)
    print("  IPLS — Enterprise Chaincode Governance Demonstration")
    print("=" * 65)

    with open("network_config.json") as f:
        config = json.load(f)

    with open("keys/OFFICIAL_A.key") as f:
        priv_A = cu.private_key_from_str(f.read().strip())
    with open("keys/OFFICIAL_B.key") as f:
        priv_B = cu.private_key_from_str(f.read().strip())

    chain = Blockchain(config)

    print("\nStep 1: Testing On-Chain Personnel Onboarding (REGISTER_EMPLOYEE)...")
    t1 = time.time()
    assert not chain.world_state.is_employee_registered("EMP2001")

    extra1 = {"department": "Cybersecurity"}
    tx_b1 = Blockchain._tx_bytes("EMP2001", "REGISTER_EMPLOYEE", "OFFICIAL_A", t1, extra_data=extra1)
    sig1 = cu.sign_bytes(priv_A, tx_b1)
    b1 = chain.build_block_from_transaction(
        "EMP2001", "REGISTER_EMPLOYEE", "OFFICIAL_A", t1, sig1,
        extra_data=extra1
    )
    chain.append_block(b1)

    assert chain.world_state.is_employee_registered("EMP2001")
    emp = chain.world_state.get_employee("EMP2001")
    assert emp["department"] == "Cybersecurity"
    print(f"  [PASS] EMP2001 onboarded on-chain into {emp['department']} department.")

    # Now EMP2001 can check in!
    t2 = t1 + 5
    tx_b2 = Blockchain._tx_bytes("EMP2001", "CHECK_IN", "OFFICIAL_A", t2)
    sig2 = cu.sign_bytes(priv_A, tx_b2)
    b2 = chain.build_block_from_transaction("EMP2001", "CHECK_IN", "OFFICIAL_A", t2, sig2)
    chain.append_block(b2)
    assert chain.world_state.get_employee("EMP2001")["status"] == "IN"
    print("  [PASS] Newly registered EMP2001 successfully checked in!")

    print("\nStep 2: Testing On-Chain Key Revocation (REVOKE_OFFICIAL)...")
    t3 = t1 + 10
    extra3 = {"target_official": "OFFICIAL_B"}
    tx_b3 = Blockchain._tx_bytes("OFFICIAL_B", "REVOKE_OFFICIAL", "OFFICIAL_A", t3, extra_data=extra3)
    sig3 = cu.sign_bytes(priv_A, tx_b3)
    b3 = chain.build_block_from_transaction(
        "OFFICIAL_B", "REVOKE_OFFICIAL", "OFFICIAL_A", t3, sig3,
        extra_data=extra3
    )
    chain.append_block(b3)
    assert chain.world_state.is_official_revoked("OFFICIAL_B")
    print("  [PASS] OFFICIAL_B permanently added to on-chain Certificate Revocation List (CRL).")

    # Verify OFFICIAL_B is blocked
    try:
        t4 = t1 + 15
        tx_b4 = Blockchain._tx_bytes("EMP1001", "CHECK_OUT", "OFFICIAL_B", t4)
        sig4 = cu.sign_bytes(priv_B, tx_b4)
        chain.build_block_from_transaction("EMP1001", "CHECK_OUT", "OFFICIAL_B", t4, sig4)
        assert False, "Should have been rejected!"
    except ContractViolation as e:
        print(f"  [PASS] Block rejected as expected: {e}")

    print("\nStep 3: Testing 2-of-N Multi-Signature Emergency Override...")
    # Re-enable OFFICIAL_B for override test in temporary state
    chain.world_state.register_official("OFFICIAL_B")

    from contract import ChaincodeEngine
    t5 = t1 + 20

    # 1-of-N fails
    extra_1ofN = {"override_status": "OUT"}
    tx_b_single = Blockchain._tx_bytes("EMP1001", "ADMIN_OVERRIDE", "OFFICIAL_A", t5, extra_data=extra_1ofN)
    sig_single = cu.sign_bytes(priv_A, tx_b_single)
    try:
        chain.build_block_from_transaction(
            "EMP1001", "ADMIN_OVERRIDE", "OFFICIAL_A", t5, sig_single,
            extra_data=extra_1ofN
        )
        assert False, "Single signature override should have failed!"
    except ContractViolation as e:
        print(f"  [PASS] 1-of-N signature rejected: {e}")

    # 2-of-N succeeds
    co_bytes = ChaincodeEngine.compute_override_co_sign_bytes("EMP1001", "OUT", "OFFICIAL_A", "OFFICIAL_B", t5)
    co_sig = cu.sign_bytes(priv_B, co_bytes)

    extra_2ofN = {
        "override_status": "OUT",
        "co_official_id": "OFFICIAL_B",
        "co_signature": co_sig,
    }
    tx_b5 = Blockchain._tx_bytes("EMP1001", "ADMIN_OVERRIDE", "OFFICIAL_A", t5, extra_data=extra_2ofN)
    sig5 = cu.sign_bytes(priv_A, tx_b5)

    b5 = chain.build_block_from_transaction(
        "EMP1001", "ADMIN_OVERRIDE", "OFFICIAL_A", t5, sig5,
        extra_data=extra_2ofN
    )
    chain.append_block(b5)
    assert chain.world_state.get_employee("EMP1001")["status"] == "OUT"
    print("  [PASS] 2-of-N Multi-Signature override successfully accepted and committed!")

    print("\n" + "=" * 65)
    print("  ALL GOVERNANCE TESTS PASSED (100% COMPLIANCE)")
    print("=" * 65)


if __name__ == "__main__":
    main()
