import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.core.crypto.password_validator import PasswordValidator


class TestPasswordValidator(unittest.TestCase):
    def setUp(self):
        self.validator = PasswordValidator()

    def test_min_length(self):
        is_valid, errors = self.validator.validate("Short1!", strict=False)
        self.assertFalse(is_valid)
        self.assertTrue(any("минимум 12 символов" in err for err in errors))

        is_valid, errors = self.validator.validate("ValidLongPass!9Q", strict=False)
        self.assertTrue(is_valid)

    def test_uppercase_required(self):
        is_valid, errors = self.validator.validate("nouppercase!9x", strict=True)
        self.assertFalse(is_valid)
        self.assertTrue(any("заглавную букву" in err for err in errors))

        is_valid, errors = self.validator.validate("ValidUpper!9xZ", strict=True)
        self.assertTrue(is_valid)

    def test_lowercase_required(self):
        is_valid, errors = self.validator.validate("NOLOWERCASE!9X", strict=True)
        self.assertFalse(is_valid)
        self.assertTrue(any("строчную букву" in err for err in errors))

        is_valid, errors = self.validator.validate("MxR!7pL#9sTa", strict=True)
        self.assertTrue(is_valid)

    def test_digits_required(self):
        is_valid, errors = self.validator.validate("NoDigitsHere!!A", strict=True)
        self.assertFalse(is_valid)
        self.assertTrue(any("цифру" in err for err in errors))

        is_valid, errors = self.validator.validate("MxR!7pL#9sTb", strict=True)
        self.assertTrue(is_valid)

    def test_special_chars_required(self):
        is_valid, errors = self.validator.validate("NoSpecial123Aa", strict=True)
        self.assertFalse(is_valid)
        self.assertTrue(any("специальный символ" in err for err in errors))

        is_valid, errors = self.validator.validate("HasSpecial!9XQ", strict=True)
        self.assertTrue(is_valid)

    def test_common_passwords(self):
        common = ["password12345", "1234567890qq", "qwerty", "admin", "welcome", "monkey", "master"]
        for pwd in common:
            is_valid, errors = self.validator.validate(pwd, strict=True)
            self.assertFalse(is_valid, f"Пароль {pwd} должен быть отклонен")
            self.assertGreater(len(errors), 0, f"Ошибка для {pwd}: {errors}")

    def test_sequences(self):
        sequences = ["abcSequence!9Q", "QwertyPass!9A", "AsdfStrong!9Q"]
        for pwd in sequences:
            is_valid, _errors = self.validator.validate(pwd, strict=True)
            self.assertFalse(is_valid, f"Пароль {pwd} должен быть отклонен")

    def test_repetitions(self):
        is_valid, errors = self.validator.validate("aaaaRepeat!9X", strict=True)
        self.assertFalse(is_valid)
        self.assertTrue(any("повторя" in err for err in errors))

        is_valid, errors = self.validator.validate("MxR!7pL#9sTc", strict=True)
        self.assertTrue(is_valid)

    def test_valid_password(self):
        good_passwords = [
            "StrongVault!9Q",
            "CorrectHorse!7Qa",
            "SafeMasterKey!8R",
            "MySecureVault!9X",
        ]

        for pwd in good_passwords:
            is_valid, errors = self.validator.validate(pwd, strict=True)
            self.assertTrue(is_valid, f"Пароль {pwd} должен быть валидным, ошибки: {errors}")

    def test_strength_score(self):
        score1 = self.validator.get_strength_score("123")
        self.assertLess(score1, 20)

        score2 = self.validator.get_strength_score("SecurePhrase!9X")
        self.assertGreaterEqual(score2, 40)
        self.assertLessEqual(score2, 80)

        score3 = self.validator.get_strength_score("StrongVault!9Q")
        self.assertGreaterEqual(score3, 70)

    def test_strength_labels(self):
        self.assertEqual(self.validator.get_strength_label(10), "Очень слабый")
        self.assertEqual(self.validator.get_strength_label(30), "Слабый")
        self.assertEqual(self.validator.get_strength_label(50), "Средний")
        self.assertEqual(self.validator.get_strength_label(70), "Хороший")
        self.assertEqual(self.validator.get_strength_label(90), "Отличный")

    def test_suggestions(self):
        weak_pwd = "123"
        suggestions = self.validator.suggest_improvements(weak_pwd)

        self.assertGreater(len(suggestions), 0)
        suggestion_text = " ".join(suggestions).lower()
        self.assertTrue("длин" in suggestion_text or "символ" in suggestion_text)


if __name__ == "__main__":
    unittest.main()