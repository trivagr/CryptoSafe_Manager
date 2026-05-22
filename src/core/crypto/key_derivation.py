from argon2 import PasswordHasher, Type
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from src.core.crypto.password_validator import validate_password
import os
import secrets



class KeyHashing:
    def __init__(self, config):
        self.hasher = PasswordHasher(
            time_cost=config["time_cost"],
            memory_cost=config["memory_cost"],
            parallelism=config["parallelism"],
            hash_len=config["hash_len"],
            salt_len=config["salt_len"],
            type=Type.ID
        )
        self.iterations = config["pbkdf2_iterations"]



    def hash_password(self, password: str):
        if validate_password(password):
            raise ValueError("Weak passwor")
        return self.hasher.hash(password)



    def password_verify(self, password: str, hashed_password: str) -> bool:

        try:
            return self.hasher.verify(hashed_password, password)
        except:
            secrets.compare_digest("a", "a")
            return False

    def salt_generate(self) -> bytes:
        return os.urandom(16)

    def derive(self, password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=self.iterations,
        )
        return kdf.derive(password.encode("utf-8"))