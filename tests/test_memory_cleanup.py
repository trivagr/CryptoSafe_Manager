from src.core.crypto.placeholder import secure_zero_bytes


def test_memory_cleanup():

    secret = bytearray(b"SUPER_SECRET_KEY")

    secure_zero_bytes(secret)

    assert all(
        x == 0
        for x in secret
    )