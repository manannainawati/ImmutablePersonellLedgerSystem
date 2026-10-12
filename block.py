"""
block.py — IPLS block structure (World State Root + BLAKE3 Merkle Root Commitment).

A block holds:
  - Standard chain linkage  : index, previous_hash, timestamp
  - Encrypted payload       : Fernet-encrypted employee data (confidentiality, if single tx)
  - Official ID             : which Higher Official authorised/proposed this block
  - Ed448 signature         : over transaction / block proposal (PoA authenticity)
  - State Root              : BLAKE3 domain-keyed hash of the World State DB (Hyperledger pattern)
  - Merkle Root             : BLAKE3 binary Merkle tree root of all transactions in this block
  - Transactions            : list of committed transaction dicts
  - Hash                    : BLAKE3 domain-keyed hash of core_fields (integrity)

PoA consensus note:
  A block is valid ONLY if:
    1. BLAKE3 hash matches its core_fields (unbroken chain linkage)
    2. Ed448 signature verifies against a registered official's public key
    3. Merkle root matches the Merkle tree of transactions
    4. Replaying transactions produces the exact State Root in the header
"""
import json
import hash_utils
from merkle_tree import MerkleTree


class Block:
    def __init__(self, index, encrypted_payload=None, official_id="SYSTEM", previous_hash="0",
                 signature=None, timestamp=None, state_root=None, merkle_root=None,
                 transactions=None, hash=None):
        self.index = index
        self.timestamp = timestamp
        self.encrypted_payload = encrypted_payload  # Fernet token (confidentiality)
        self.official_id = official_id              # which official authorised this
        self.previous_hash = previous_hash
        self.signature = signature                  # Ed448 sig over tx (PoA authenticity)
        self.state_root = state_root                # BLAKE3 hash of World State DB
        self.transactions = transactions or []

        # If transactions provided and merkle_root not specified, compute from transactions
        if self.transactions and not merkle_root:
            self.merkle_root = MerkleTree(self.transactions).root
        elif not merkle_root:
            # Fallback to single payload or default root
            fallback_items = [encrypted_payload] if encrypted_payload else ["GENESIS"]
            self.merkle_root = MerkleTree(fallback_items).root
        else:
            self.merkle_root = merkle_root

        self.hash = hash

    # ------------------------------------------------------------------
    # The fields that are hashed and thus immutably committed to the chain.
    # Changing ANY of these bytes invalidates the hash.
    # ------------------------------------------------------------------
    def core_fields(self) -> bytes:
        payload = {
            "index": self.index,
            "timestamp": self.timestamp,
            "encrypted_payload": self.encrypted_payload,
            "official_id": self.official_id,
            "previous_hash": self.previous_hash,
            "signature": self.signature,
            "state_root": self.state_root,
            "merkle_root": self.merkle_root,
        }
        return json.dumps(payload, sort_keys=True).encode()

    def compute_hash(self) -> str:
        """Compute the BLAKE3 domain-keyed hash of this block's core fields."""
        return hash_utils.compute_block_hash(self.core_fields())

    def to_dict(self):
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "encrypted_payload": self.encrypted_payload,
            "official_id": self.official_id,
            "previous_hash": self.previous_hash,
            "signature": self.signature,
            "state_root": self.state_root,
            "merkle_root": self.merkle_root,
            "transactions": self.transactions,
            "hash": self.hash,
        }

    @staticmethod
    def from_dict(d):
        b = Block(
            index=d["index"],
            encrypted_payload=d.get("encrypted_payload"),
            official_id=d["official_id"],
            previous_hash=d["previous_hash"],
            signature=d.get("signature"),
            timestamp=d["timestamp"],
            state_root=d.get("state_root"),
            merkle_root=d.get("merkle_root"),
            transactions=d.get("transactions", []),
        )
        b.hash = d["hash"]
        return b
