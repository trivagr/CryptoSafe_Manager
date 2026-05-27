from src.core.crypto.key_derivation import KeyHashing


def test_key_consistency():

    hashing = KeyHashing()

    password = "TestPassword123"

    salt = b"1234567890123456"

    first = hashing.derive(password, salt)

    for i in range(100):

        current = hashing.derive(password, salt)

        assert current == first