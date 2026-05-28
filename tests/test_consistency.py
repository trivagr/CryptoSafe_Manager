from src.core.crypto.key_derivation import KeyHashing
from src.core.crypto.placeholder import secure_zero_bytes


def test_key_consistency():

    hashing = KeyHashing()

    password = b"TestPassword123"

    salt = b"1234567890123456"

    first = hashing.derive(password, salt)

    for _ in range(100):

        current = hashing.derive(password, salt)

        assert current == first

    first_bytes = bytearray(first)

    secure_zero_bytes(first_bytes)

    del first_bytes