"""
crypto_utils.py — Cryptographic utilities for IPLS.

Security layers
---------------
  Ed448 (RFC 8032, Goldilocks curve)   — transaction authenticity
      Every attendance record is signed by the originating official's
      Ed448 private key.  Nodes verify the signature using only the
      official's public key, which is baked into network_config.json
      before the network launches.  Private keys never touch a node.

  Fernet (AES-128-CBC + HMAC-SHA256)   — payload confidentiality
      Employee data (name / ID / action) is encrypted inside each block
      using a shared facility key established at network-setup time.
      The facility key is symmetric and kept out of the public config on
      a real deployment; here it lives in network_config.json only
      because this is a single-facility local demo.

WHY Ed448 (Goldilocks) over NIST P-256?
-----------------------------------------
  | Property           | NIST P-256 (old)           | Ed448 (new)              |
  |--------------------|----------------------------|--------------------------|
  | Security level     | 128-bit                    | 224-bit (significantly   |
  |                    |                            | stronger)                |
  | Curve constants    | NIST random seed — origin  | Rigid / nothing-up-my-   |
  |                    | disputed                   | sleeve (Goldilocks prime) |
  | Twist security     | No                         | Yes                      |
  | Small-subgroup     | Cofactor 1, vulnerable     | Cofactor 4, protected    |
  | Side-channel       | Library-dependent          | Edwards math inherently  |
  |                    |                            | constant-time            |
  | Standard           | NIST FIPS 186              | RFC 8032 (IETF)          |
  | Blockchain usage   | Very common (ETH, etc.)    | Almost never used        |

  Ed448 is provided by Python's `cryptography` library which was already
  in requirements.txt.  No new dependency is introduced.
"""

import base64
import json

from cryptography.hazmat.primitives.asymmetric.ed448 import (
    Ed448PrivateKey,
    Ed448PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    PrivateFormat,
    NoEncryption,
)
from cryptography.exceptions import InvalidSignature
from cryptography.fernet import Fernet


# ── Digital signatures — Ed448 (RFC 8032) ────────────────────────────────────

def generate_official_keypair():
    """
    Generate a fresh Ed448 key pair.

    Returns (private_key, public_key) as Ed448PrivateKey / Ed448PublicKey
    objects from the `cryptography` library.

    The private key is saved to disk only by setup_network.py (simulating
    an official's own device / smart card).  It is NEVER held by a node
    process; nodes only know the public key.
    """
    private_key = Ed448PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


def sign_bytes(private_key: Ed448PrivateKey, data: bytes) -> str:
    """
    Sign *data* with *private_key* (Ed448) and return a base64url string.

    Ed448 produces a 114-byte deterministic signature (no random nonce —
    the randomness is derived from the private key and message internally,
    giving resilience against bad RNG at signing time).
    """
    return base64.b64encode(private_key.sign(data)).decode()


def verify_signature(public_key: Ed448PublicKey, data: bytes, signature_b64: str) -> bool:
    """
    Return True iff *signature_b64* is a valid Ed448 signature over *data*
    by the holder of the private key corresponding to *public_key*.

    Any malformed input or invalid signature returns False — never raises.
    """
    if not signature_b64:
        return False
    try:
        sig_bytes = base64.b64decode(signature_b64)
        public_key.verify(sig_bytes, data)
        return True
    except (InvalidSignature, Exception):
        return False


def public_key_to_str(public_key: Ed448PublicKey) -> str:
    """
    Serialise a public key to a base64-encoded DER string.

    DER encoding (SubjectPublicKeyInfo format) is the IETF-standard
    wire format for Ed448 public keys and is unambiguous — no curve
    parameter needs to be passed when deserialising.
    """
    der = public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    return base64.b64encode(der).decode()


def public_key_from_str(s: str) -> Ed448PublicKey:
    """Deserialise a base64-DER public key string produced by public_key_to_str."""
    from cryptography.hazmat.primitives.serialization import load_der_public_key
    return load_der_public_key(base64.b64decode(s))


def private_key_to_str(private_key: Ed448PrivateKey) -> str:
    """
    Serialise a private key to a base64-encoded DER string (PKCS8 format,
    unencrypted).

    Only ever called by setup_network.py to write the key to a local file
    that simulates the official's own device.  The node process never
    calls this function.
    """
    der = private_key.private_bytes(
        Encoding.DER,
        PrivateFormat.PKCS8,
        NoEncryption(),
    )
    return base64.b64encode(der).decode()


def private_key_from_str(s: str) -> Ed448PrivateKey:
    """Deserialise a base64-DER private key string produced by private_key_to_str."""
    from cryptography.hazmat.primitives.serialization import load_der_private_key
    return load_der_private_key(base64.b64decode(s), password=None)


# ── Symmetric encryption — Fernet (AES-128-CBC + HMAC-SHA256) ────────────────

def generate_facility_key() -> bytes:
    """Generate a fresh Fernet key (32 cryptographically random bytes, base64url)."""
    return Fernet.generate_key()


def encrypt_payload(fernet_key: bytes, payload: dict) -> str:
    """
    JSON-serialise *payload* and encrypt it with the shared facility key.
    Returns a Fernet token (base64url string) safe to store in a block.
    """
    f = Fernet(fernet_key)
    return f.encrypt(json.dumps(payload, sort_keys=True).encode()).decode()


def decrypt_payload(fernet_key: bytes, token: str) -> dict:
    """
    Decrypt and JSON-deserialise a Fernet token.
    Raises cryptography.fernet.InvalidToken if the key is wrong or the
    token has been tampered with.
    """
    f = Fernet(fernet_key)
    return json.loads(f.decrypt(token.encode()).decode())
