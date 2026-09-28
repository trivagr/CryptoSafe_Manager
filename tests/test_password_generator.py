import os
import sys
import time
import unittest

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.core.vault.password_generator import (
    AMBIGUOUS_CHARACTERS,
    PasswordGenerator,
    PasswordGeneratorOptions,
    SYMBOLS,
)


class TestPasswordGenerator(unittest.TestCase):
    def setUp(self):
        self.generator = PasswordGenerator()

    def test_generate_uses_requested_length(self):
        password = self.generator.generate(PasswordGeneratorOptions(length=24))
        self.assertEqual(len(password), 24)

    def test_generate_includes_each_selected_charset(self):
        password = self.generator.generate(
            PasswordGeneratorOptions(
                length=20,
                include_uppercase=True,
                include_lowercase=True,
                include_digits=True,
                include_symbols=True,
            )
        )

        self.assertTrue(any(char.isupper() for char in password))
        self.assertTrue(any(char.islower() for char in password))
        self.assertTrue(any(char.isdigit() for char in password))
        self.assertTrue(any(char in SYMBOLS for char in password))

    def test_generate_can_exclude_ambiguous_characters(self):
        password = self.generator.generate(
            PasswordGeneratorOptions(length=20, exclude_ambiguous=True, include_symbols=False)
        )

        self.assertTrue(all(char not in AMBIGUOUS_CHARACTERS for char in password))

    def test_generate_rejects_when_no_charset_enabled(self):
        with self.assertRaises(ValueError):
            self.generator.generate(
                PasswordGeneratorOptions(
                    include_uppercase=False,
                    include_lowercase=False,
                    include_digits=False,
                    include_symbols=False,
                )
            )

    def test_recent_history_tracks_generated_passwords(self):
        generator = PasswordGenerator(history_limit=3)
        passwords = [generator.generate(PasswordGeneratorOptions(length=16)) for _ in range(3)]

        self.assertEqual(generator.recent_passwords(), passwords)

    def test_strength_check_rejects_weak_passwords(self):
        self.assertFalse(self.generator.is_strong_enough("aaaaaaaaaaaa"))
        self.assertFalse(self.generator.is_strong_enough("Password123"))
        self.assertTrue(self.generator.is_strong_enough("Strong!Pass123"))

    def test_bulk_generation_respects_character_sets_and_history(self):
        generator = PasswordGenerator(history_limit=20)
        generated_passwords = []

        for _ in range(200):
            password = generator.generate(
                PasswordGeneratorOptions(
                    length=18,
                    include_uppercase=True,
                    include_lowercase=True,
                    include_digits=True,
                    include_symbols=True,
                    exclude_ambiguous=True,
                )
            )
            generated_passwords.append(password)

            self.assertEqual(len(password), 18)
            self.assertTrue(any(char.isupper() for char in password))
            self.assertTrue(any(char.islower() for char in password))
            self.assertTrue(any(char.isdigit() for char in password))
            self.assertTrue(any(char in SYMBOLS for char in password))
            self.assertTrue(all(char not in AMBIGUOUS_CHARACTERS for char in password))
            self.assertTrue(generator.is_strong_enough(password))

        self.assertEqual(len(generated_passwords), len(set(generated_passwords)))
        self.assertEqual(generator.recent_passwords(), generated_passwords[-20:])

    @pytest.mark.slow
    def test_generate_10000_passwords_without_duplicates_and_with_required_strength(self):
        generator = PasswordGenerator(history_limit=20)
        options = PasswordGeneratorOptions(
            length=20,
            include_uppercase=True,
            include_lowercase=True,
            include_digits=True,
            include_symbols=True,
            exclude_ambiguous=True,
        )
        generated_passwords = []

        started_at = time.perf_counter()
        for _ in range(10000):
            password = generator.generate(options)
            generated_passwords.append(password)

            self.assertEqual(len(password), 20)
            self.assertTrue(any(char.isupper() for char in password))
            self.assertTrue(any(char.islower() for char in password))
            self.assertTrue(any(char.isdigit() for char in password))
            self.assertTrue(any(char in SYMBOLS for char in password))
            self.assertTrue(all(char not in AMBIGUOUS_CHARACTERS for char in password))
            self.assertTrue(generator.is_strong_enough(password))

        elapsed = time.perf_counter() - started_at

        self.assertEqual(len(generated_passwords), len(set(generated_passwords)))
        self.assertEqual(generator.recent_passwords(), generated_passwords[-20:])
        self.assertLess(elapsed, 15.0)


if __name__ == "__main__":
    unittest.main()