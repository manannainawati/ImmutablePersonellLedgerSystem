"""
official_client.py — Signs and submits attendance transactions on behalf of an official.

This script stands in for the official's own device (phone / smart card).
It is the ONLY component that ever reads a private key file.  The key
never leaves this process; only the resulting Ed448 signature is sent
over the network.

Usage:
    python official_client.py OFFICIAL_A EMP1001 CHECK_IN --node http://localhost:5000

The private key file (keys/OFFICIAL_A.key) is a base64-encoded DER
(PKCS8) Ed448 private key written by setup_network.py.
"""

import argparse
import json
import time

import requests
import crypto_utils as cu


def submit(official_id, employee_id, action, node_url, keyfile=None):
    """
    Sign an attendance transaction with the official's Ed448 private key
    and POST it to the specified node.

    Returns the requests.Response object so callers can inspect the result.
    """
    keyfile = keyfile or f"keys/{official_id}.key"
    with open(keyfile) as f:
        private_key = cu.private_key_from_str(f.read().strip())

    timestamp = time.time()
    tx_bytes = json.dumps(
        {
            "employee_id": employee_id,
            "action": action,
            "official_id": official_id,
            "timestamp": timestamp,
        },
        sort_keys=True,
    ).encode()

    # Ed448 sign — 114-byte deterministic signature (no RNG at signing time)
    signature = cu.sign_bytes(private_key, tx_bytes)

    return requests.post(
        f"{node_url}/transactions/submit",
        json={
            "employee_id": employee_id,
            "action": action,
            "official_id": official_id,
            "timestamp": timestamp,
            "signature": signature,
        },
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="IPLS Official Client — signs attendance transactions"
    )
    parser.add_argument("official_id", help="e.g. OFFICIAL_A")
    parser.add_argument("employee_id", help="e.g. EMP1001")
    parser.add_argument("action", choices=["CHECK_IN", "CHECK_OUT"])
    parser.add_argument("--node", default="http://localhost:5000")
    parser.add_argument("--keyfile", default=None,
                        help="path to the official's .key file (default: keys/{official_id}.key)")
    args = parser.parse_args()

    resp = submit(args.official_id, args.employee_id, args.action, args.node, args.keyfile)
    print(resp.status_code, resp.json())
