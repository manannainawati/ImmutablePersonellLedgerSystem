"""
demos/demo_tamper_heal.py — Multi-Node Tamper Detection & Nakamoto Self-Healing Demo.

Demonstrates:
  1. Bootstraps 3 clean nodes on localhost:5000, 5001, 5002
  2. Submits an official transaction replicating Block #1 across the cluster
  3. Simulates a local disk corruption attack on Node 5001 Block #1
  4. Verifies Node 5001 instantly flags its local ledger as INVALID
  5. Triggers Nakamoto longest-valid-chain resolution (/nodes/resolve)
  6. Verifies Node 5001 self-heals back to 100% validity from peer consensus

Usage:
    python demos/demo_tamper_heal.py
"""

import os
import sys
import subprocess
import time
import requests

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from official_client import submit


def main():
    ports = [5000, 5001, 5002]
    procs = []
    print("=" * 65)
    print("  IPLS — Tamper Detection & Self-Healing Demonstration")
    print("=" * 65)

    print("\nStep 1: Launching 3-node network...")
    try:
        for p in ports:
            proc = subprocess.Popen(
                [sys.executable, "node.py", "--port", str(p), "--clean"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            procs.append(proc)

        # Wait for nodes to initialize
        for p in ports:
            online = False
            for _ in range(30):
                try:
                    res = requests.get(f"http://localhost:{p}/chain", timeout=0.8)
                    if res.status_code == 200:
                        online = True
                        break
                except Exception:
                    time.sleep(0.3)
            assert online, f"Node {p} failed to boot within timeout"
        print("  [PASS] All 3 nodes online and healthy at Genesis.")

        # Post a transaction to create Block #1
        print("\nStep 2: Submitting an authorized transaction from official client...")
        submit("OFFICIAL_A", "EMP1001", "CHECK_IN", "http://localhost:5000")
        time.sleep(1.5)

        # Check all 3 nodes have 2 blocks (Genesis + Block 1)
        for p in ports:
            chain = requests.get(f"http://localhost:{p}/chain").json()
            assert len(chain) == 2, f"Node {p} expected 2 blocks, got {len(chain)}"
            assert all(b["valid"] for b in chain), f"Node {p} has invalid block!"
        print("  [PASS] All 3 nodes replicated Block #1 with 100% validity.")

        # Step 3: Tamper attack on Node 5001
        print("\nStep 3: Simulating local tamper attack on Node 5001 Block #1...")
        tamper_res = requests.post(
            "http://localhost:5001/debug/tamper_local_block",
            json={"block_index": 1},
            timeout=2
        ).json()
        print(f"  Tamper injection status: {tamper_res.get('message')}")

        # Check Node 5001 is invalid
        chain_5001 = requests.get("http://localhost:5001/chain").json()
        assert not chain_5001[1]["valid"], "Node 5001 Block 1 must be flagged INVALID!"
        assert not chain_5001[1]["hash_ok"], "Node 5001 hash check must fail!"
        print("  [PASS] Node 5001 independently caught the tamper attack.")

        # Nodes 5000 and 5002 remain completely unaffected
        for p in [5000, 5002]:
            chain = requests.get(f"http://localhost:{p}/chain").json()
            assert all(b["valid"] for b in chain), f"Node {p} should be healthy!"
        print("  [PASS] Nodes 5000 and 5002 are completely uncompromised.")

        # Step 4: Auto-Heal Node 5001 via consensus resolution
        print("\nStep 4: Triggering Nakamoto Longest-Valid Consensus Auto-Healing...")
        resolve_res = requests.post("http://localhost:5001/nodes/resolve", timeout=2).json()
        print(f"  Resolution result: {resolve_res.get('message')}")
        assert resolve_res["replaced"], "Chain on Node 5001 should have been replaced!"

        # Step 5: Verify Node 5001 is now 100% healed
        healed_chain = requests.get("http://localhost:5001/chain").json()
        assert all(b["valid"] for b in healed_chain), "Node 5001 should be 100% valid after healing!"
        print("  [PASS] Node 5001 has restored authentic ledger history and is back in sync!")

        print("\n" + "=" * 65)
        print("  TAMPER DETECTION & NAKAMOTO AUTO-HEALING CONFIRMED")
        print("=" * 65)

    finally:
        for p in procs:
            p.terminate()
        print("\nStopped test nodes.")


if __name__ == "__main__":
    main()
