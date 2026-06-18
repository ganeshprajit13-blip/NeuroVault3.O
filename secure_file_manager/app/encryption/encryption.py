from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet, InvalidToken
import hashlib
import os
import base64
import binascii

class EncryptionManager:
    def __init__(self):
        self.backend = default_backend()

    @staticmethod
    def _fernet(app_secret: str) -> Fernet:
        secret = (app_secret or '').strip()
        key = base64.urlsafe_b64encode(hashlib.sha256(secret.encode('utf-8')).digest())
        return Fernet(key)

    def seal_aes_key_for_storage(self, aes_key: bytes, app_secret: str) -> str:
        """Wrap AES key so download can recover it using the same app SECRET_KEY."""
        return self._fernet(app_secret).encrypt(aes_key).decode('ascii')

    def unseal_aes_key_from_storage(self, sealed: str, app_secret: str) -> bytes:
        """Unwrap AES key written by seal_aes_key_for_storage."""
        return self.unwrap_stored_aes_key(sealed, app_secret)

    @staticmethod
    def unwrap_stored_aes_key(stored, app_secret: str) -> bytes:
        """
        Recover AES key from DB: Fernet token (current format), or raw 32-byte key base64-encoded.
        Normalizes whitespace/BOM so keys still work if the DB or env had hidden characters.
        """
        if stored is None:
            raise InvalidToken
        s = str(stored).strip().replace('\ufeff', '').strip()
        if not s:
            raise InvalidToken
        fernet = EncryptionManager._fernet(app_secret)
        try:
            return fernet.decrypt(s.encode('utf-8'))
        except InvalidToken:
            pass
        try:
            raw = base64.b64decode(s, validate=False)
        except binascii.Error:
            raise InvalidToken from None
        if len(raw) == 32:
            return raw
        raise InvalidToken

    def generate_rsa_keys(self):
        """Generate RSA key pair for key exchange"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=self.backend
        )
        public_key = private_key.public_key()
        return private_key, public_key

    def serialize_public_key(self, public_key):
        """Serialize public key to PEM format"""
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pem.decode('utf-8')

    def load_public_key(self, pem_data):
        """Load public key from PEM data"""
        public_key = serialization.load_pem_public_key(
            pem_data.encode('utf-8'),
            backend=self.backend
        )
        return public_key

    def generate_aes_key(self):
        """Generate a random AES key"""
        return os.urandom(32)  # 256-bit key

    def encrypt_aes_key(self, aes_key, public_key):
        """Encrypt AES key with RSA public key"""
        encrypted_key = public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return base64.b64encode(encrypted_key).decode('utf-8')

    def decrypt_aes_key(self, encrypted_aes_key, private_key):
        """Decrypt AES key with RSA private key"""
        encrypted_key = base64.b64decode(encrypted_aes_key)
        aes_key = private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return aes_key

    def encrypt_file(self, file_data, aes_key):
        """Encrypt file data using AES"""
        iv = os.urandom(16)  # Initialization vector
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=self.backend)
        encryptor = cipher.encryptor()

        # Pad the data to be multiple of block size
        block_size = 16
        padding_length = block_size - (len(file_data) % block_size)
        padded_data = file_data + bytes([padding_length]) * padding_length

        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        return iv + encrypted_data  # Prepend IV

    def decrypt_file(self, encrypted_data, aes_key):
        """Decrypt file data using AES"""
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]

        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=self.backend)
        decryptor = cipher.decryptor()
        decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()

        # Remove padding
        padding_length = decrypted_padded[-1]
        decrypted_data = decrypted_padded[:-padding_length]
        return decrypted_data

    def hash_file(self, file_data):
        """Generate SHA-256 hash of file"""
        digest = hashes.Hash(hashes.SHA256(), backend=self.backend)
        digest.update(file_data)
        return digest.finalize().hex()