"""
demos/demo_crypto_tamper.py — Standalone Cryptographic & Tamper-Resistance Demonstration.

Demonstrates the core cryptographic properties of IPLS without needing running network daemons:
  1. Legitimate block creation with Ed448 digital signatures + BLAKE3 domain hashing.
  2. Smart contract state transition validation.
  3. Attack 1: Naive tampering (modifying data without recomputing hashes)
     -> Caught immediately by BLAKE3 domain hash integrity check.
  4. Attack 2: Sophisticated tampering (modifying data AND recomputing hash chain)
     -> Hash chain passes, but fails Ed448 signature verification!
     -> Proves PoA: an attacker cannot forge records without the official's private key.

Usage:
    python demos/demo_crypto_tamper.py
"""

import os
import sys
import time

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from blockchain import Blockchain
import crypto_utils as cu


def show_validity(chain, label):
    print(f"\n--- {label} ---")
    for result in chain.is_chain_valid():
        status = "OK" if result["valid"] else "TAMPERED / INVALID"
        print(f"  Block {result['index']}: hash_ok={result['hash_ok']}  "
              f"sig_ok={result['signature_ok']}  rule_ok={result['contract_ok']}  -> {status}")


def build_sample_chain():
    priv_A, pub_A = cu.generate_official_keypair()
    priv_B, pub_B = cu.generate_official_keypair()

    config = {
        "facility_key": cu.generate_facility_key().decode(),
        "officials": {
            "OFFICIAL_A": cu.public_key_to_str(pub_A),
            "OFFICIAL_B": cu.public_key_to_str(pub_B),
        },
        "personnel_registry": ["EMP1001", "EMP1002", "EMP1003", "EMP1004"],
        "peers": [],
    }
    chain = Blockchain(config)

    def add(emp, action, off_id, priv_key):
        ts = time.time()
        tx_bytes = Blockchain._tx_bytes(emp, action, off_id, ts)
        sig = cu.sign_bytes(priv_key, tx_bytes)
        blk = chain.build_block_from_transaction(emp, action, off_id, ts, sig)
        chain.append_block(blk)

    add("EMP1001", "CHECK_IN", "OFFICIAL_A", priv_A)
    add("EMP1002", "CHECK_IN", "OFFICIAL_B", priv_B)
    add("EMP1001", "CHECK_OUT", "OFFICIAL_A", priv_A)
    return chain, config, (priv_A, priv_B)


def main():
    print("=" * 65)
    print("  IPLS — Standalone Cryptographic & Tamper Verification Demo")
    print("=" * 65)

    chain, config, (priv_A, priv_B) = build_sample_chain()
    show_validity(chain, "STEP 1: Legitimate chain (3 blocks appended)")

    # ── Attack 1 ─────────────────────────────────────────────────────────────
    print("\n" + "=" * 65)
    print("ATTACK 1: Naive attacker modifies Block 1 data on disk/memory")
    print("           (changes payload without updating the block hash)")
    print("=" * 65)

    original_payload = chain.chain[1].encrypted_payload
    chain.chain[1].encrypted_payload = "ATTACKER_CORRUPTED_PAYLOAD"
    show_validity(chain, "Result of Attack 1")
    print("\nOutcome: Block 1 fails hash check; Block 2 fails previous_hash check.")
    print("Ledger integrity is preserved — the tampering is detected immediately.")

    chain.chain[1].encrypted_payload = original_payload

    # ── Attack 2 ─────────────────────────────────────────────────────────────
    print("\n" + "=" * 65)
    print("ATTACK 2: Sophisticated attacker modifies Block 1 AND recomputes")
    print("           the BLAKE3 hash chain forward through Block 3.")
    print("=" * 65)

    forged_bytes = cu.encrypt_payload(
        chain.facility_key,
        {"employee_id": "EMP1004", "action": "CHECK_IN", "timestamp": chain.chain[1].timestamp},
    )
    chain.chain[1].encrypted_payload = forged_bytes
    chain.chain[1].hash = chain.chain[1].compute_hash()

    for i in range(2, len(chain.chain)):
        chain.chain[i].previous_hash = chain.chain[i - 1].hash
        chain.chain[i].hash = chain.chain[i].compute_hash()

    show_validity(chain, "Result of Attack 2")
    print("\nOutcome: The hash chain is mathematically consistent (hash_ok=True),")
    print("BUT Block 1 fails signature_ok because the attacker does NOT have")
    print("OFFICIAL_A's Ed448 private key. A valid hash is not enough under PoA.")

    print("\n" + "=" * 65)
    print("  DEMO COMPLETE: Proof of Authority guarantees authenticity.")
    print("=" * 65)


if __name__ == "__main__":
    main()
