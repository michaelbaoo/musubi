from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
from cryptography.hazmat.backends import default_backend
import base64
import os
from typing import Optional
from loguru import logger

class EncryptionManager:
    def __init__(self, key: Optional[str] = None):
        if key:
            self.cipher = Fernet(key.encode())
        else:
            self.cipher = self._generate_cipher_from_env()
    
    def _generate_cipher_from_env(self) -> Fernet:
        encryption_key = os.getenv("ENCRYPTION_KEY")
        
        if not encryption_key:
            # Generate a new key if not provided
            key = Fernet.generate_key()
            logger.warning("No encryption key provided, generated new key")
            logger.info(f"Save this key securely: {key.decode()}")
            return Fernet(key)
        
        # Derive key from password
        kdf = PBKDF2(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'stable_salt_for_app',  # In production, use random salt
            iterations=100000,
            backend=default_backend()
        )
        
        key = base64.urlsafe_b64encode(kdf.derive(encryption_key.encode()))
        return Fernet(key)
    
    def encrypt(self, data: str) -> str:
        try:
            encrypted = self.cipher.encrypt(data.encode())
            return base64.urlsafe_b64encode(encrypted).decode()
        except Exception as e:
            logger.error(f"Encryption failed: {e}")
            raise
    
    def decrypt(self, encrypted_data: str) -> str:
        try:
            decoded = base64.urlsafe_b64decode(encrypted_data.encode())
            decrypted = self.cipher.decrypt(decoded)
            return decrypted.decode()
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            raise
    
    def encrypt_email_content(self, content: str) -> str:
        # Compress and encrypt email content
        import zlib
        compressed = zlib.compress(content.encode())
        encrypted = self.cipher.encrypt(compressed)
        return base64.urlsafe_b64encode(encrypted).decode()
    
    def decrypt_email_content(self, encrypted_content: str) -> str:
        import zlib
        decoded = base64.urlsafe_b64decode(encrypted_content.encode())
        decrypted = self.cipher.decrypt(decoded)
        decompressed = zlib.decompress(decrypted)
        return decompressed.decode()
    
    def hash_password(self, password: str) -> str:
        import bcrypt
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password.encode(), salt)
        return hashed.decode()
    
    def verify_password(self, password: str, hashed: str) -> bool:
        import bcrypt
        return bcrypt.checkpw(password.encode(), hashed.encode())