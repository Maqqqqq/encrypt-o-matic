import os
import hashlib
import hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

# Twofish: pure Python implementation (Bjorn Edstrom / Dr Brian Gladman)
from twofish_pure import Twofish as TwofishCipher


class EncryptionManager:
    """Manager for file encryption operations"""

    PAYLOAD_VERSION = 1

    def __init__(self, algorithm: str, password: str):
        """
        Initialize encryption manager
        
        Args:
            algorithm: Encryption algorithm (AES, ChaCha20, Twofish)
            password: Password for encryption
        """
        self.algorithm = algorithm.upper()
        self.password = password

    def _require_supported_algorithm(self):
        """Raise a clear error for unsupported algorithms."""
        if self.algorithm not in {"AES", "CHACHA20", "TWOFISH"}:
            raise ValueError(f"Unsupported algorithm: {self.algorithm}")

    def _derive_key(self, salt: bytes, dklen: int = 32) -> bytes:
        """Derive key from password using scrypt."""
        return hashlib.scrypt(
            self.password.encode("utf-8"),
            salt=salt,
            n=2**14,
            r=8,
            p=1,
            dklen=dklen,
        )
    
    def encrypt(self, data: bytes) -> bytes:
        """
        Encrypt data
        
        Args:
            data: Data to encrypt
            
        Returns:
            Encrypted data
        """
        self._require_supported_algorithm()
        if self.algorithm == "AES":
            return self._encrypt_aes(data)
        if self.algorithm == "CHACHA20":
            return self._encrypt_chacha20(data)
        return self._encrypt_twofish(data)
    
    def decrypt(self, encrypted_data: bytes) -> bytes:
        """
        Decrypt data
        
        Args:
            encrypted_data: Encrypted data
            
        Returns:
            Decrypted data
        """
        self._require_supported_algorithm()
        if self.algorithm == "AES":
            return self._decrypt_aes(encrypted_data)
        if self.algorithm == "CHACHA20":
            return self._decrypt_chacha20(encrypted_data)
        return self._decrypt_twofish(encrypted_data)
    
    def _encrypt_aes(self, data: bytes) -> bytes:
        """Encrypt using AES-256-GCM."""
        salt = os.urandom(16)
        nonce = os.urandom(12)
        key = self._derive_key(salt, dklen=32)
        ciphertext = AESGCM(key).encrypt(nonce, data, None)
        return bytes([self.PAYLOAD_VERSION]) + salt + nonce + ciphertext
    
    def _decrypt_aes(self, encrypted_data: bytes) -> bytes:
        """Decrypt using AES-256-GCM."""
        if len(encrypted_data) < 1 + 16 + 12 + 16:
            raise ValueError("Invalid AES payload length")
        version = encrypted_data[0]
        if version != self.PAYLOAD_VERSION:
            raise ValueError("Unsupported AES payload version")
        salt = encrypted_data[1:17]
        nonce = encrypted_data[17:29]
        ciphertext = encrypted_data[29:]
        key = self._derive_key(salt, dklen=32)
        return AESGCM(key).decrypt(nonce, ciphertext, None)
    
    def _encrypt_chacha20(self, data: bytes) -> bytes:
        """Encrypt using ChaCha20-Poly1305."""
        salt = os.urandom(16)
        key = self._derive_key(salt, dklen=32)
        chacha = ChaCha20Poly1305(key)
        nonce = os.urandom(12)
        ciphertext = chacha.encrypt(nonce, data, None)
        return bytes([self.PAYLOAD_VERSION]) + salt + nonce + ciphertext
    
    def _decrypt_chacha20(self, encrypted_data: bytes) -> bytes:
        """Decrypt using ChaCha20-Poly1305."""
        if len(encrypted_data) < 1 + 16 + 12 + 16:
            raise ValueError("Invalid ChaCha20 payload length")
        version = encrypted_data[0]
        if version != self.PAYLOAD_VERSION:
            raise ValueError("Unsupported ChaCha20 payload version")
        salt = encrypted_data[1:17]
        nonce = encrypted_data[17:29]
        ciphertext = encrypted_data[29:]
        key = self._derive_key(salt, dklen=32)
        chacha = ChaCha20Poly1305(key)
        return chacha.decrypt(nonce, ciphertext, None)
    
    def _encrypt_twofish(self, data: bytes) -> bytes:
        """Encrypt using Twofish-CBC + HMAC-SHA256 (encrypt-then-MAC)."""
        salt = os.urandom(16)
        key_material = self._derive_key(salt, dklen=64)
        enc_key = key_material[:32]
        mac_key = key_material[32:]

        iv = os.urandom(16)

        # Add padding to multiple of 16 bytes
        pad_length = 16 - (len(data) % 16)
        padded_data = data + bytes([pad_length] * pad_length)

        cipher = TwofishCipher(enc_key)
        ciphertext = bytearray()
        prev_block = iv

        for i in range(0, len(padded_data), 16):
            block = padded_data[i : i + 16]
            xored = bytes(a ^ b for a, b in zip(block, prev_block))
            encrypted_block = cipher.encrypt(xored)
            ciphertext.extend(encrypted_block)
            prev_block = encrypted_block

        raw = iv + bytes(ciphertext)
        tag = hmac.new(mac_key, raw, hashlib.sha256).digest()
        return bytes([self.PAYLOAD_VERSION]) + salt + raw + tag
    
    def _decrypt_twofish(self, encrypted_data: bytes) -> bytes:
        """Decrypt using Twofish-CBC + HMAC-SHA256 (encrypt-then-MAC)."""
        if len(encrypted_data) < 1 + 16 + 16 + 16 + 32:
            raise ValueError("Invalid Twofish payload length")

        version = encrypted_data[0]
        if version != self.PAYLOAD_VERSION:
            raise ValueError("Unsupported Twofish payload version")

        salt = encrypted_data[1:17]
        body = encrypted_data[17:-32]
        tag = encrypted_data[-32:]

        key_material = self._derive_key(salt, dklen=64)
        enc_key = key_material[:32]
        mac_key = key_material[32:]
        expected = hmac.new(mac_key, body, hashlib.sha256).digest()
        if not hmac.compare_digest(tag, expected):
            raise ValueError("Twofish integrity check failed")

        iv = body[:16]
        ciphertext = body[16:]
        if len(ciphertext) % 16 != 0:
            raise ValueError("Invalid Twofish ciphertext alignment")

        cipher = TwofishCipher(enc_key)
        plaintext = bytearray()
        prev_block = iv

        for i in range(0, len(ciphertext), 16):
            block = ciphertext[i : i + 16]
            decrypted_block = cipher.decrypt(block)
            xored = bytes(a ^ b for a, b in zip(decrypted_block, prev_block))
            plaintext.extend(xored)
            prev_block = block

        pad_length = plaintext[-1]
        if pad_length <= 0 or pad_length > 16:
            raise ValueError("Invalid Twofish padding")
        return bytes(plaintext[:-pad_length])
