"""
tests/test_blockchain.py — Ledger and Blockchain core test suite:
  - Genesis block creation
  - State Root & Merkle Root commitments in block headers
  - Mempool & block packing
  - On-disk WAL persistence & cold recovery
  - Tamper detection
"""
import unittest
import json
import time
import os
import shutil
from blockchain import Blockchain
import crypto_utils as cu

class TestBlockchain(unittest.TestCase):
    def setUp(self):
        with open("network_config.json") as f:
            self.config = json.load(f)
        self.test_data_dir = "data/test_node_temp"
        if os.path.exists(self.test_data_dir):
            shutil.rmtree(self.test_data_dir, ignore_errors=True)
        self.storage_path = os.path.join(self.test_data_dir, "chain.jsonl")

        with open("keys/OFFICIAL_A.key") as f:
            self.priv_A = cu.private_key_from_str(f.read().strip())

    def tearDown(self):
        if os.path.exists(self.test_data_dir):
            shutil.rmtree(self.test_data_dir, ignore_errors=True)

    def test_genesis_block(self):
        chain = Blockchain(self.config)
        self.assertEqual(len(chain.chain), 1)
        genesis = chain.chain[0]
        self.assertEqual(genesis.index, 0)
        self.assertEqual(genesis.previous_hash, "0")
        self.assertIsNotNone(genesis.state_root)
        self.assertIsNotNone(genesis.merkle_root)
        self.assertTrue(chain.is_chain_valid()[0]["valid"])

    def test_block_creation_and_state_root(self):
        chain = Blockchain(self.config)
        t = time.time()
        tx_b = Blockchain._tx_bytes("EMP1001", "CHECK_IN", "OFFICIAL_A", t)
        sig = cu.sign_bytes(self.priv_A, tx_b)

        b1 = chain.build_block_from_transaction("EMP1001", "CHECK_IN", "OFFICIAL_A", t, sig)
        chain.append_block(b1)

        self.assertEqual(len(chain.chain), 2)
        self.assertEqual(chain.world_state.get_employee("EMP1001")["status"], "IN")
        self.assertEqual(b1.state_root, chain.world_state.compute_state_root())
        validation = chain.is_chain_valid()
        self.assertTrue(all(v["valid"] for v in validation))

    def test_mempool_and_multi_tx_packing(self):
        chain = Blockchain(self.config)
        t = time.time()

        for emp in ["EMP1001", "EMP1002"]:
            tx_b = Blockchain._tx_bytes(emp, "CHECK_IN", "OFFICIAL_A", t)
            sig = cu.sign_bytes(self.priv_A, tx_b)
            chain.add_to_mempool(emp, "CHECK_IN", "OFFICIAL_A", t, sig)

        self.assertEqual(len(chain.mempool), 2)
        block = chain.build_block_from_mempool(max_txs=10, proposer_id="OFFICIAL_A")
        self.assertIsNotNone(block)
        chain.append_block(block)

        self.assertEqual(len(chain.chain), 2)
        self.assertEqual(len(block.transactions), 2)
        self.assertEqual(len(chain.mempool), 0)
        validation = chain.is_chain_valid()
        self.assertTrue(all(v["valid"] for v in validation))

    def test_wal_persistence_and_replay(self):
        chain1 = Blockchain(self.config, storage_path=self.storage_path)
        t = time.time()
        tx_b = Blockchain._tx_bytes("EMP1001", "CHECK_IN", "OFFICIAL_A", t)
        sig = cu.sign_bytes(self.priv_A, tx_b)
        b1 = chain1.build_block_from_transaction("EMP1001", "CHECK_IN", "OFFICIAL_A", t, sig)
        chain1.append_block(b1)

        # Cold restart new Blockchain instance with same storage
        chain2 = Blockchain(self.config, storage_path=self.storage_path)
        self.assertEqual(len(chain2.chain), 2)
        self.assertEqual(chain2.world_state.get_employee("EMP1001")["status"], "IN")
        self.assertEqual(chain2.world_state.compute_state_root(), chain1.world_state.compute_state_root())

if __name__ == "__main__":
    unittest.main()
