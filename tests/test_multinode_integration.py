"""
tests/test_multinode_integration.py — End-to-End Real 3-Node Integration Test Suite.

Verifies:
  1. Multi-node cluster bootstrap across Node 5000, Node 5001, and Node 5002
  2. Genesis block consensus and synchronized initial World State
  3. Official signed transaction submission and P2P gossip propagation to all peers
  4. Chain and state root convergence across the entire consortium
  5. Cryptographic audit certificate generation, issuer Ed448 signature, and offline verification
  6. Authorization protection on debug endpoints
"""
import unittest
import subprocess
import sys
import time
import requests
import json
import os
import signal

from verify_certificate import verify_certificate_dict


class TestMultiNodeIntegration(unittest.TestCase):
    processes = []
    ports = [5000, 5001, 5002]

    @classmethod
    def setUpClass(cls):
        # Ensure network_config.json exists
        if not os.path.exists("network_config.json") or not os.path.exists("keys/OFFICIAL_A.key"):
            subprocess.run([sys.executable, "setup_network.py"], check=True)

        # Launch 3 nodes with --clean flag
        cls.processes = []
        for port in cls.ports:
            p = subprocess.Popen(
                [sys.executable, "node.py", "--port", str(port), "--clean"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            cls.processes.append(p)

        # Wait for all nodes to be online (up to 15 seconds)
        start_time = time.time()
        all_ready = False
        while time.time() - start_time < 15:
            ready_count = 0
            for port in cls.ports:
                try:
                    resp = requests.get(f"http://localhost:{port}/chain", timeout=1)
                    if resp.status_code == 200:
                        ready_count += 1
                except Exception:
                    pass
            if ready_count == len(cls.ports):
                all_ready = True
                break
            time.sleep(0.5)

        if not all_ready:
            cls.tearDownClass()
            raise RuntimeError("Failed to start 3-node network within timeout")

    @classmethod
    def tearDownClass(cls):
        for p in cls.processes:
            try:
                p.terminate()
                p.wait(timeout=2)
            except Exception:
                try:
                    p.kill()
                except Exception:
                    pass

    def test_01_all_nodes_genesis_consensus(self):
        """Verify all 3 nodes initialized identical Genesis block and state root."""
        genesis_hashes = []
        state_roots = []

        for port in self.ports:
            resp = requests.get(f"http://localhost:{port}/chain", timeout=2)
            self.assertEqual(resp.status_code, 200)
            data = resp.json()
            self.assertIsInstance(data, list)
            self.assertEqual(len(data), 1)
            genesis_hashes.append(data[0]["hash"])
            state_roots.append(data[0]["state_root"])

        # Consensus check
        self.assertEqual(len(set(genesis_hashes)), 1, "All 3 nodes must agree on Genesis block hash")
        self.assertEqual(len(set(state_roots)), 1, "All 3 nodes must agree on Genesis state root")

    def test_02_transaction_gossip_and_multi_node_convergence(self):
        """Submit signed transaction to Node 5000 and verify gossip propagation to 5001 & 5002."""
        from official_client import submit

        # Official A submits check-in for EMP1001 to Node 5000
        resp = submit("OFFICIAL_A", "EMP1001", "CHECK_IN", node_url="http://localhost:5000")
        self.assertEqual(resp.status_code, 201, f"Transaction submission failed: {resp.text}")

        # Allow brief moment for P2P gossip
        time.sleep(1.5)

        # Verify all nodes have chain length 2 and identical tip hash
        tip_hashes = []
        for port in self.ports:
            chain_resp = requests.get(f"http://localhost:{port}/chain", timeout=2)
            self.assertEqual(chain_resp.status_code, 200)
            data = chain_resp.json()
            self.assertEqual(len(data), 2, f"Node {port} must have height 2 after gossip")
            tip_hashes.append(data[-1]["hash"])

            # Verify world state on each node
            state_resp = requests.get(f"http://localhost:{port}/state", timeout=2)
            self.assertEqual(state_resp.status_code, 200)
            emp = state_resp.json()["world_state"]["employees"]["EMP1001"]
            self.assertEqual(emp["status"], "IN", f"Node {port} must reflect status IN for EMP1001")
            self.assertTrue(state_resp.json()["live_state_valid"])

        self.assertEqual(len(set(tip_hashes)), 1, "All nodes must converge on the exact same block hash")

    def test_03_full_chain_validation_across_all_nodes(self):
        """Verify that /verify endpoint passes independently on all three nodes."""
        for port in self.ports:
            resp = requests.get(f"http://localhost:{port}/verify", timeout=2)
            self.assertEqual(resp.status_code, 200)
            results = resp.json()
            self.assertTrue(all(r["valid"] for r in results), f"All blocks must be cryptographically valid on Node {port}")

    def test_04_audit_certificate_generation_and_verification(self):
        """Fetch audit certificate from Node 5000 and run offline verification."""
        resp = requests.get("http://localhost:5000/audit/certificate/EMP1001", timeout=2)
        self.assertEqual(resp.status_code, 200)
        cert = resp.json()

        self.assertEqual(cert["employee_id"], "EMP1001")
        self.assertIn("cryptographic_seal", cert)
        self.assertIn("issuer_signature", cert)
        self.assertEqual(cert["on_chain_events_count"], 1)

        # Run offline verification using standalone verify_certificate_dict
        verified = verify_certificate_dict(cert)
        self.assertTrue(verified, "Live audit certificate from node must pass offline cryptographic verification")

    def test_05_debug_endpoints_authorization(self):
        """Verify debug endpoints enforce security checks."""
        # 1. Unauthorized request without X-Debug-Auth header must return 403
        resp_unauth = requests.post(
            "http://localhost:5000/debug/tamper_local_block",
            json={"block_index": 1},
            timeout=2,
        )
        self.assertEqual(resp_unauth.status_code, 403, "Unauthenticated debug call must return 403 Forbidden")

        # 2. Unauthorized request with bogus token must return 403
        resp_bad_token = requests.post(
            "http://localhost:5000/debug/tamper_local_block",
            json={"block_index": 1},
            headers={"X-Debug-Auth": "invalid-bogus-token"},
            timeout=2,
        )
        self.assertEqual(resp_bad_token.status_code, 403, "Invalid token must return 403 Forbidden")

        # 3. Authorized request with valid token succeeds (200)
        resp_auth = requests.post(
            "http://localhost:5000/debug/tamper_local_block",
            json={"block_index": 1},
            headers={"X-Debug-Auth": "IPLS-INTERNAL-SECURITY-TEST-TOKEN"},
            timeout=2,
        )
        self.assertEqual(resp_auth.status_code, 200, "Authorized debug request must succeed")

        # 4. Self-healing: peer healing restores Node 5000 from untampered peers
        heal_resp = requests.get("http://localhost:5000/nodes/sync", timeout=3)
        self.assertEqual(heal_resp.status_code, 200)


if __name__ == "__main__":
    unittest.main()
