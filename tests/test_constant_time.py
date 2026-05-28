import time

from src.core.crypto.key_derivation import KeyHashing


def test_constant_time():

    hashing = KeyHashing()

    password = b"CorrectPass123?"
    wrong = b"WrongPass123?"

    hashed = hashing.hash_password(password)

    start = time.perf_counter()

    for i in range(30):
        hashing.password_verify(password, hashed)

    valid_time = time.perf_counter() - start

    start = time.perf_counter()

    for i in range(30):
        hashing.password_verify(wrong, hashed)

    invalid_time = time.perf_counter() - start

    diff = abs(valid_time - invalid_time)

    assert diff < 0.5