import hashlib
from argon2 import PasswordHasher, Type
from argon2.exceptions import VerifyMismatchError

Argon2_time_cost = 3
Argon2_memory_cost = 65536
Argon2_parallelism = 4
Argon2_hash_len = 32
Argon2_salt_len = 16

def hash_password(password):
    password_hasher = PasswordHasher(Argon2_hash_len, Argon2_memory_cost, Argon2_parallelism, Argon2_hash_len, Argon2_salt_len, type=Type.ID)

    return password_hasher.hash(password)



def password_verify(hashed_password, password):
    password_hasher = PasswordHasher(Argon2_hash_len, Argon2_memory_cost, Argon2_parallelism, Argon2_hash_len, Argon2_salt_len, type=Type.ID)

    try:
        return password_hasher.verify(hashed_password, password)
    except VerifyMismatchError:
        return False



def key_derive(password, salt):
    derived_key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100000, 32)

    return derived_key