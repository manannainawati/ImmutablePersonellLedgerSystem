"""
tests/test_crypto.py — Cryptographic operations test suite:
  - Ed448 digital signatures (RFC 8032)
  - BLAKE3 domain-keyed hashing
  - Fernet AES-128 payload confidentiality
"""
import unittest
import crypto_utils as cu
import hash_utils

class TestCrypto(unittest.TestCase):
    def setUp(self):
        self.priv, self.pub = cu.generate_official_keypair()
        self.key_bytes = cu.generate_facility_key()

    def test_ed448_sign_and_verify(self):
        message = b"EMP1001:CHECK_IN:1728000000"
        sig = cu.sign_bytes(self.priv, message)
        self.assertIsInstance(sig, str)
        self.assertTrue(cu.verify_signature(self.pub, message, sig))

    def test_ed448_tampered_message_fails(self):
        message = b"EMP1001:CHECK_IN:1728000000"
        sig = cu.sign_bytes(self.priv, message)
        tampered_msg = b"EMP1001:CHECK_OUT:1728000000"
        self.assertFalse(cu.verify_signature(self.pub, tampered_msg, sig))

    def test_ed448_invalid_key_fails(self):
        other_priv, other_pub = cu.generate_official_keypair()
        message = b"EMP1001:CHECK_IN:1728000000"
        sig = cu.sign_bytes(self.priv, message)
        self.assertFalse(cu.verify_signature(other_pub, message, sig))

    def test_blake3_domain_separation(self):
        import blake3
        data = b"block_header_data_sample"
        block_h = hash_utils.compute_block_hash(data)
        state_h = hash_utils.compute_state_hash(data)
        plain_h = blake3.blake3(data).hexdigest()

        # Domain separation guarantees all three are distinct for identical input bytes
        self.assertNotEqual(block_h, state_h)
        self.assertNotEqual(block_h, plain_h)
        self.assertNotEqual(state_h, plain_h)
        self.assertEqual(len(block_h), 64)

    def test_fernet_confidentiality(self):
        payload = {"employee_id": "EMP1001", "action": "CHECK_IN", "secret": "internal_facility_token"}
        ciphertext = cu.encrypt_payload(self.key_bytes, payload)
        self.assertIsInstance(ciphertext, str)
        self.assertNotIn("EMP1001", ciphertext)

        decrypted = cu.decrypt_payload(self.key_bytes, ciphertext)
        self.assertEqual(decrypted["employee_id"], "EMP1001")
        self.assertEqual(decrypted["secret"], "internal_facility_token")

if __name__ == "__main__":
    unittest.main()
