from argon2 import PasswordHasher, Type
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from src.core.crypto.password_validator import validate_password
from src.core.config import ConfigManager
import os
import secrets



class KeyHashing:
    def __init__(self):
        config = ConfigManager()
        self.hasher = PasswordHasher(
            time_cost=config.argon2["time_cost"],
            memory_cost=config.argon2["memory_cost"],
            parallelism=config.argon2["parallelism"],
            hash_len=config.argon2["hash_len"],
            salt_len=config.argon2["salt_len"],
            type=Type.ID
        )
        self.iterations = config.pbkdf2["iterations"]

    def hash_password(self, password: bytes):
        password_str = password.decode()

        try:
            if not validate_password(password_str):
                raise ValueError("Weak password")

            return self.hasher.hash(password_str)

        finally:

            del password_str


    def password_verify(self, password: bytes, hashed_password: str) -> bool:
        password_str = password.decode()

        try:
            return self.hasher.verify(hashed_password, password_str)

        except:
            secrets.compare_digest(os.urandom(32), os.urandom(32))
            return False

        finally:
            del password_str


    def salt_generate(self) -> bytes:
        return os.urandom(16)


    def derive(self, password: bytes, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=self.iterations,
        )
        return kdf.derive(bytes(password))