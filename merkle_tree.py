"""
merkle_tree.py — Cryptographic Merkle Tree using domain-keyed BLAKE3.

In Bitcoin, Ethereum, and enterprise blockchains:
  • Transactions within a block are hashed into a binary Merkle Tree.
  • The MERKLE ROOT is a 256-bit hash committed into the block header.
  • Merkle trees allow Simplified Payment Verification (SPV): an auditor or
    client can mathematically verify that transaction T was committed into
    block B in O(log N) time using only a Merkle audit path, without
    downloading the entire block or the rest of the blockchain.

Domain Separation (RFC 6962 / Certificate Transparency standard):
  • Leaf hash:      BLAKE3(b"\\x00" + tx_bytes)
  • Internal node:  BLAKE3(b"\\x01" + left_hash + right_hash)
This cryptographic prefix prevents second-preimage collision attacks.
"""

import json
import blake3
import hash_utils


def hash_leaf(data: bytes) -> str:
    """Hash a leaf node with 0x00 domain separator prefix."""
    return blake3.blake3(b"\x00" + data).hexdigest()


def hash_internal(left_hex: str, right_hex: str) -> str:
    """Hash an internal tree node with 0x01 domain separator prefix."""
    left_bytes = bytes.fromhex(left_hex)
    right_bytes = bytes.fromhex(right_hex)
    return blake3.blake3(b"\x01" + left_bytes + right_bytes).hexdigest()


class MerkleTree:
    """
    Binary Merkle Tree for transaction sets within an IPLS block.
    """

    def __init__(self, items=None):
        """
        items: list of bytes or dicts (serialized canonically).
        """
        self.leaf_hashes = []
        self.levels = []

        if items:
            for item in items:
                if isinstance(item, dict):
                    raw = json.dumps(item, sort_keys=True).encode()
                elif isinstance(item, str):
                    raw = item.encode()
                else:
                    raw = bytes(item)
                self.leaf_hashes.append(hash_leaf(raw))

            self._build_tree()
        else:
            # Empty tree representation
            self.levels = [["0" * 64]]

    def _build_tree(self):
        if not self.leaf_hashes:
            self.levels = [["0" * 64]]
            return

        current_level = list(self.leaf_hashes)
        self.levels = [current_level]

        while len(current_level) > 1:
            next_level = []
            # If odd number of nodes at this level, duplicate the last node (standard Bitcoin rule)
            if len(current_level) % 2 != 0:
                current_level.append(current_level[-1])

            for i in range(0, len(current_level), 2):
                combined = hash_internal(current_level[i], current_level[i + 1])
                next_level.append(combined)

            self.levels.append(next_level)
            current_level = next_level

    @property
    def root(self) -> str:
        """Returns the 256-bit hex Merkle Root."""
        if not self.levels or not self.levels[-1]:
            return "0" * 64
        return self.levels[-1][0]

    def get_proof(self, index: int) -> list:
        """
        Generate an SPV Merkle audit proof for the item at `index`.
        Returns a list of sibling hashes and their positions:
            [{"position": "left"|"right", "hash": "..."}]
        """
        if index < 0 or index >= len(self.leaf_hashes):
            raise IndexError("Leaf index out of bounds")

        proof = []
        idx = index

        for level_idx in range(len(self.levels) - 1):
            level = self.levels[level_idx]
            # Account for duplicated odd element
            if len(level) % 2 != 0:
                level = level + [level[-1]]

            is_right_child = (idx % 2 == 1)
            sibling_idx = idx - 1 if is_right_child else idx + 1

            if sibling_idx < len(level):
                sibling_hash = level[sibling_idx]
                proof.append({
                    "position": "left" if is_right_child else "right",
                    "hash": sibling_hash,
                })

            idx = idx // 2

        return proof

    @staticmethod
    def verify_proof(item, proof: list, expected_root: str) -> bool:
        """
        Verify that `item` is committed under `expected_root` using `proof`.
        Runs in O(log N) time with zero knowledge of the other transactions!
        """
        if isinstance(item, dict):
            raw = json.dumps(item, sort_keys=True).encode()
        elif isinstance(item, str):
            raw = item.encode()
        else:
            raw = bytes(item)

        current_hash = hash_leaf(raw)

        for step in proof:
            sibling_hash = step["hash"]
            pos = step["position"]

            if pos == "left":
                current_hash = hash_internal(sibling_hash, current_hash)
            elif pos == "right":
                current_hash = hash_internal(current_hash, sibling_hash)
            else:
                return False  # Strictly reject malformed proof steps

        return current_hash.lower() == expected_root.lower()
