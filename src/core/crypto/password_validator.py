import re

common_patterns = {
    "password",
    "qwerty",
    "111111",
    "admin",
    "12345",
    "222222",
    "333333",
    "444444",
    "555555",
    "666666",
    "777777",
    "888888",
    "999999"
}

def validate_password(password: str) -> bool:

    if len(password) < 12:
        return False

    has_upper = bool(re.search(r"[A-Z]", password))
    has_lower = bool(re.search(r"[a-z]", password))
    has_digit = bool(re.search(r"[0-9]", password))
    has_special = bool(re.search(r"[!@#$%^&*()_+={};':|,.<>?~`-]", password))

    if not(has_upper and has_lower and has_digit and has_special):
        return False

    for pattern in common_patterns:
        if pattern in password.lower():
            return False

    return True