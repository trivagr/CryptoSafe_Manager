from src.core.vault.password_generator import PasswordGenerator

from zxcvbn import zxcvbn


def test_password_generator():

    generator = PasswordGenerator()

    passwords = set()

    allowed = set(generator._filter(generator.LOWER) + generator._filter(generator.UPPER) + generator._filter(generator.DIGITS) + generator._filter(generator.SYMBOLS))

    for i in range(10000):
        password = (generator.generate())

        passwords.add(password)

        for ch in password:
            assert (ch in allowed)

        score = (zxcvbn(password).get("score",0))

        assert score >= 3

        assert len(password) >= 8

    assert len(passwords) > 9900