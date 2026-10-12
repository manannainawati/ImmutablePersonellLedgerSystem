"""
tests/test_merkle.py — BLAKE3 binary Merkle trees and SPV audit proof tests:
  - RFC 6962 leaf/node domain hashing
  - Deterministic root hash
  - Inclusion proof generation & verification
  - Proof rejection on tampered transactions
"""
import unittest
from merkle_tree import MerkleTree

class TestMerkleTree(unittest.TestCase):
    def setUp(self):
        self.txs = [
            {"employee_id": f"EMP100{i}", "action": "CHECK_IN", "nonce": i}
            for i in range(1, 9)
        ]
        self.tree = MerkleTree(self.txs)

    def test_merkle_root_deterministic(self):
        tree2 = MerkleTree(self.txs)
        self.assertEqual(self.tree.root, tree2.root)
        self.assertEqual(len(self.tree.root), 64)

    def test_spv_inclusion_proof_valid(self):
        # Verify inclusion of each leaf in the tree
        for i, tx in enumerate(self.txs):
            proof = self.tree.get_proof(i)
            self.assertTrue(MerkleTree.verify_proof(tx, proof, self.tree.root))

    def test_spv_tampered_transaction_rejected(self):
        proof = self.tree.get_proof(0)
        tampered_tx = {"employee_id": "EMP1001", "action": "CHECK_OUT", "nonce": 1}
        self.assertFalse(MerkleTree.verify_proof(tampered_tx, proof, self.tree.root))

    def test_spv_tampered_sibling_hash_rejected(self):
        proof = self.tree.get_proof(0)
        tampered_proof = list(proof)
        # Flip first character of the sibling hash
        sibling = tampered_proof[0]
        flipped_hash = ("0" if sibling["hash"][0] != "0" else "1") + sibling["hash"][1:]
        tampered_proof[0] = {"position": sibling["position"], "hash": flipped_hash}
        self.assertFalse(MerkleTree.verify_proof(self.txs[0], tampered_proof, self.tree.root))

    def test_odd_leaves_handling(self):
        odd_txs = self.txs[:5]
        tree_odd = MerkleTree(odd_txs)
        for i, tx in enumerate(odd_txs):
            proof = tree_odd.get_proof(i)
            self.assertTrue(MerkleTree.verify_proof(tx, proof, tree_odd.root))

if __name__ == "__main__":
    unittest.main()
