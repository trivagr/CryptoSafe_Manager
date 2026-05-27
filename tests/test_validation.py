from src.core.crypto.key_derivation import KeyHashing


def test_argon2_validation():

    hashing = KeyHashing()

    passwords = [
        "ChupepAbebAbeb228!",
        "AnotherGnida911@",
        "GigigagaDopustim6769#"
    ]

    for password in passwords:

        hashed = (hashing.hash_password(password))

        result = (hashing.password_verify(password, hashed))

        assert result is True