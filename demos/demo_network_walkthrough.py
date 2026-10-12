"""
demos/demo_network_walkthrough.py — Interactive Step-by-Step P2P Network Walkthrough.

Demonstrates:
  1. Verifying Genesis block replication across all 3 nodes
  2. Submitting legitimate transactions from official client
  3. Replicating state across nodes
  4. Contract rule violation defense (double check-in rejection)
  5. Cryptographic signature forgery rejection

Usage:
    python demos/demo_network_walkthrough.py
    (Ensure 'python run_network.py' is running in another window)
"""

import os
import sys
import time
import requests

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from official_client import submit

NODES = [
    "http://localhost:5000",
    "http://localhost:5001",
    "http://localhost:5002",
]


def section(title):
    print()
    print("=" * 65)
    print(f"  {title}")
    print("=" * 65)


def step(n, title):
    print()
    print(f"STEP {n}: {title}")
    print("-" * 65)


def main():
    print("Checking if IPLS network nodes are online...")
    for url in NODES:
        try:
            requests.get(f"{url}/chain", timeout=1.5)
        except Exception:
            print(f"Error: Node at {url} is unreachable.")
            print("Please run 'python run_network.py' in a separate terminal before running this walkthrough.")
            sys.exit(1)

    section("IPLS LIVE NETWORK WALKTHROUGH")

    # ── Step 1: Query Genesis State ──────────────────────────────────────────
    step(1, "GENESIS STATE ACROSS ALL 3 NODES")
    for url in NODES:
        c = requests.get(f"{url}/chain").json()
        b = c[0]
        print(f"  {url}")
        print(f"    Total Blocks : {len(c)}")
        print(f"    Genesis Hash : {b['hash'][:32]}...")
        print(f"    Valid        : {b['valid']}")

    # ── Step 2: First Authorized Transaction ─────────────────────────────────
    step(2, "OFFICIAL_A submits EMP1001 CHECK_IN -> Node 5000")
    r = submit("OFFICIAL_A", "EMP1001", "CHECK_IN", "http://localhost:5000")
    resp = r.json()
    blk = resp.get("block", {})
    print(f"  HTTP Status      : {r.status_code} | Accepted: {resp.get('accepted')}")
    print(f"  Block Index      : #{blk.get('index')}")
    print(f"  Official ID      : {blk.get('official_id')}")
    print(f"  Hash (BLAKE3)    : {blk.get('hash', '')[:32]}...")
    print(f"  State Root       : {blk.get('state_root', '')[:32]}...")

    # Wait for gossip broadcast
    time.sleep(1)

    # ── Step 3: Gossip Verification ──────────────────────────────────────────
    step(3, "GOSSIP BROADCAST VERIFICATION ACROSS NODES")
    for url in NODES:
        c = requests.get(f"{url}/chain").json()
        latest = c[-1]
        print(f"  {url} -> Height: {len(c)} blocks | Latest Hash: {latest['hash'][:24]}... | Valid: {latest['valid']}")

    # ── Step 4: Contract Violation ───────────────────────────────────────────
    step(4, "CHAINCODE RULE DEFENSE: Double Check-In Rejection")
    print("Attempting to CHECK_IN EMP1001 again without checking out first...")
    r2 = submit("OFFICIAL_B", "EMP1001", "CHECK_IN", "http://localhost:5000")
    print(f"  HTTP Status: {r2.status_code}")
    print(f"  Rejection Response: {r2.text}")

    # ── Step 5: Forgery Rejection ────────────────────────────────────────────
    step(5, "BYZANTINE DEFENSE: PoA Signature Forgery Attack")
    print("Broadcasting block with simulated forged signature from Node 5000...")
    forge_res = requests.post("http://localhost:5000/debug/forge_and_broadcast", json={
        "employee_id": "EMP1003", "action": "CHECK_IN", "official_id": "OFFICIAL_A"
    }).json()
    print("  Peer responses:")
    for peer, reply in forge_res.items():
        print(f"    {peer} -> {reply}")

    section("WALKTHROUGH DEMO COMPLETED SUCCESSFULLY")


if __name__ == "__main__":
    main()
