import secrets
import hashlib
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError



def hash_password(password):
    password_hasher = PasswordHasher(3, 65536, 4, 32, 16)

    return password_hasher.hash(password)



def password_verify(hashed_password, password):
    password_hasher = PasswordHasher(3, 65536, 4, 32, 16)

    try:
        return password_hasher.verify(hashed_password, password)
    except VerifyMismatchError:
        return False



def slat_generation():
    salt = secrets.token_bytes(16)

    return salt



def key_derive(password, salt):
    derived_key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100000, 32)

    return derived_key