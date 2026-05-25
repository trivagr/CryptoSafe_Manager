import secrets
from collections import deque
from zxcvbn import zxcvbn
from src.core.config import ConfigManager



class PasswordGenerator:

    LOWER = "abcdefghijklmnopqrstuvwxyz"
    UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    DIGITS = "0123456789"
    SYMBOLS = "!@#$%^&*"

    AMBIGUOUS = set("lI10O")

    def __init__(self):
        self.config = ConfigManager()
        self.history = deque(maxlen=20)


    def generate(
        self,
        length: int = 0,
        use_lower: bool = True,
        use_upper: bool = True,
        use_digits: bool = True,
        use_symbols: bool = True
    ) -> str:
        length = length or self.config.password_generator["length"]

        if not (8 <= length <= 64):
            raise ValueError("Length must be between 8 and 64")

        pools = []

        if use_lower:
            pools.append(self._filter(self.LOWER))
        if use_upper:
            pools.append(self._filter(self.UPPER))
        if use_digits:
            pools.append(self._filter(self.DIGITS))
        if use_symbols:
            pools.append(self._filter(self.SYMBOLS))

        if not pools:
            raise ValueError("No character sets selected")

        password_chars = []

        for pool in pools:
            password_chars.append(secrets.choice(pool))

        all_chars = "".join(pools)

        while len(password_chars) < length:
            password_chars.append(secrets.choice(all_chars))

        secrets.SystemRandom().shuffle(password_chars)

        password = "".join(password_chars)

        if password in self.history:
            return self.generate(length, use_lower, use_upper, use_digits, use_symbols)

        score = zxcvbn(password).get("score", 0)
        if score < 3:
            return self.generate(length, use_lower, use_upper, use_digits, use_symbols)

        self.history.append(password)

        return password

    def _filter(self, chars: str) -> str:
        return "".join(c for c in chars if c not in self.AMBIGUOUS)