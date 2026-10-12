"""
setup_network.py — One-time network initialisation for IPLS.

Run once, before starting any node:

    python setup_network.py

Generates:
  keys/OFFICIAL_A.key, keys/OFFICIAL_B.key
      Each official's Ed448 private key (DER/PKCS8, base64-encoded).
      These simulate the key living on each official's own device /
      smart card. They are NEVER read by node.py — only
      official_client.py (standing in for the official's own app)
      reads them.

  network_config.json
      The genesis configuration every node loads at startup:
        - officials          : map of official_id → Ed448 public key (DER/b64)
        - personnel_registry : list of valid employee IDs
        - facility_key       : Fernet symmetric key for payload encryption
        - peers              : list of node URLs

      The hash algorithm is NOT in the config — it is fixed to BLAKE3
      with domain separation and cannot be changed at runtime. Removing
      this knob eliminates the security downgrade path that a pluggable-
      algorithm field would represent.

Consensus model: Proof of Authority (PoA)
  Authority is delegated to the registered Higher Officials whose
  Ed448 public keys are baked into network_config.json here.
  Only they can produce valid signatures → only their transactions
  become blocks. Every node enforces this independently.

Ed448 key properties vs NIST P-256 (what was here before):
  Security level : 224-bit  (was 128-bit)
  Curve          : Goldilocks — rigid, nothing-up-my-sleeve constants
  Twist secure   : yes       (P-256: no)
  Side-channel   : Edwards math is inherently constant-time
  Standard       : RFC 8032  (P-256: NIST FIPS 186, disputed seed)
"""

import json
import os

import crypto_utils as cu


def main():
    os.makedirs("keys", exist_ok=True)
    officials = {}

    for oid in ("OFFICIAL_A", "OFFICIAL_B"):
        private_key, public_key = cu.generate_official_keypair()
        # Save private key as base64-encoded DER (PKCS8).
        # Only official_client.py reads this; node.py never touches it.
        with open(f"keys/{oid}.key", "w") as f:
            f.write(cu.private_key_to_str(private_key))
        officials[oid] = cu.public_key_to_str(public_key)

    config = {
        "personnel_registry": ["EMP1001", "EMP1002", "EMP1003", "EMP1004"],
        "officials": officials,
        "facility_key": cu.generate_facility_key().decode(),
        "peers": [
            "http://localhost:5000",
            "http://localhost:5001",
            "http://localhost:5002",
        ],
        # NOTE: no hash_algo field — BLAKE3 (domain-keyed) is fixed in code.
        # No config knob = no downgrade path.
    }

    with open("network_config.json", "w") as f:
        json.dump(config, f, indent=2)

    print("=" * 60)
    print("IPLS Network Setup Complete")
    print("=" * 60)
    print()
    print("Consensus model : Proof of Authority (PoA)")
    print("                  Only registered Higher Officials can")
    print("                  produce valid blocks (Ed448 signatures).")
    print()
    print("Key algorithm   : Ed448 (RFC 8032, Goldilocks curve)")
    print("                  224-bit security | twist-safe | rigid constants")
    print()
    print("Hash algorithm  : BLAKE3 (domain-keyed, FIXED)")
    print("                  Context: 'IPLS-attendance-block-hash-v1'")
    print("                  No pluggable-algo config knob.")
    print("                  One algorithm. One construction. Always.")
    print()
    print("Generated files:")
    print("  network_config.json   — loaded by every node at startup (public config)")
    print("  keys/OFFICIAL_A.key   — OFFICIAL_A's Ed448 private key (keep secret)")
    print("  keys/OFFICIAL_B.key   — OFFICIAL_B's Ed448 private key (keep secret)")
    print()
    print("IMPORTANT: keys/*.key simulate each official's own device.")
    print("  node.py NEVER reads them. Only official_client.py does.")
    print()
    print("To start the network:")
    print("  python node.py --port 5000   # terminal 1")
    print("  python node.py --port 5001   # terminal 2")
    print("  python node.py --port 5002   # terminal 3")
    print()
    print("To submit a transaction:")
    print("  python official_client.py OFFICIAL_A EMP1001 CHECK_IN --node http://localhost:5000")


if __name__ == "__main__":
    main()
