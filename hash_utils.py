"""
hash_utils.py — BLAKE3 domain-keyed block hashing for IPLS.

Algorithm: BLAKE3 with a fixed domain-separation context string.
----------------------------------------------------------------------
WHY BLAKE3?
  - 2020 standard; designed by the authors of BLAKE2, ChaCha20, and Bao.
  - Internal Merkle-tree construction (Bao) gives inherent domain
    separation — fundamentally different from sequential SHA/SHA-3 family.
  - Faster than SHA-256, SHA-3-256, and BLAKE2b on all platforms.
  - Post-quantum: no known quantum speedup beyond Grover's √N attack;
    256-bit output → 128-bit quantum security (same as AES-128).
  - Almost NO production blockchain uses BLAKE3
    (Bitcoin→SHA-256, Ethereum→Keccak-256, Zcash→BLAKE2s,
     Filecoin→SHA2-256-trunc254padded, Nano→Blake2b).
    Maximum novelty; genuine cryptographic strength.

DOMAIN SEPARATION (single generation technique)
  blake3(data, key=DOMAIN_KEY)
  where DOMAIN_KEY = blake3.derive_key(DOMAIN_CONTEXT_STRING, b"")

  This is the standard BLAKE3 keyed-hash construction. The same raw
  bytes fed to a plain BLAKE3 and to this domain-keyed BLAKE3 produce
  completely different outputs, preventing:
    - Cross-protocol key reuse / confusion attacks
    - Downgrade to unkeyed BLAKE3 by a misconfigured peer

  The context string is permanently burned into the code. There is NO
  config knob to select a different algorithm — that knob would be a
  security downgrade path, and we have eliminated it entirely.
  One algorithm. One construction. Always.

All functions produce a 64-character hex digest (256-bit output).
"""

import blake3 as _blake3

# ── Domain separation ────────────────────────────────────────────────────────

DOMAIN_CONTEXT = b"IPLS-attendance-block-hash-v1"

# Derive a 32-byte key from the context string via BLAKE3's derive_key mode.
# derive_key() is BLAKE3's official API for this exact purpose (RFC-style KDF).
_DOMAIN_KEY: bytes = _blake3.blake3(DOMAIN_CONTEXT, derive_key_context="IPLS derive").digest()


# ── Core hash primitive ──────────────────────────────────────────────────────

def compute_block_hash(data: bytes) -> str:
    """
    Return the BLAKE3 domain-keyed hex digest of *data*.

    Uses BLAKE3's keyed-hash mode: blake3(data, key=_DOMAIN_KEY).
    The 32-byte key makes this a completely distinct hash function from
    unkeyed BLAKE3 — same security argument as HMAC vs bare hash, but
    integrated into BLAKE3's compression rather than wrapped around it.

    Output: lowercase 64-character hex string (256-bit).
    """
    return _blake3.blake3(data, key=_DOMAIN_KEY).hexdigest()


# ── World State root hash primitive ──────────────────────────────────────────

STATE_DOMAIN_CONTEXT = b"IPLS-world-state-hash-v1"
_STATE_DOMAIN_KEY: bytes = _blake3.blake3(STATE_DOMAIN_CONTEXT, derive_key_context="IPLS derive").digest()

def compute_state_hash(data: bytes) -> str:
    """
    Return the BLAKE3 domain-keyed hex digest for World State commitment (State Root).
    Ensures domain separation so state roots cannot be confused with block hashes.
    """
    return _blake3.blake3(data, key=_STATE_DOMAIN_KEY).hexdigest()

