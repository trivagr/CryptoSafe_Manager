import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.core.config import Config
from src.core.security import apply_security_profile, get_security_profile, validate_security_settings


class TestConfig(unittest.TestCase):
    def setUp(self):
        # Создаём временную домашнюю директорию для изоляции тестов конфига.
        self.test_dir = tempfile.mkdtemp()
        self.original_home = Path.home
        Path.home = lambda: Path(self.test_dir)

    def tearDown(self):
        Path.home = self.original_home
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_default_config(self):
        config = Config()

        self.assertEqual(config.get("security.clipboard_timeout"), 30)
        self.assertEqual(config.get("security.auto_lock_minutes"), 5)
        self.assertEqual(config.get("security.security_profile"), "standard")
        self.assertTrue(config.get("security.memory_locking_enabled"))

    def test_set_and_get(self):
        config = Config()

        config.set("appearance.theme", "dark")
        config.set("security.clipboard_timeout", 45)

        self.assertEqual(config.get("appearance.theme"), "dark")
        self.assertEqual(config.get("security.clipboard_timeout"), 45)

    def test_nested_keys(self):
        config = Config()
        config.set("security.clipboard_timeout", 60)

        self.assertEqual(config.get("security.clipboard_timeout"), 60)
        self.assertEqual(config.get("security.auto_lock_minutes"), 5)

    def test_default_value(self):
        config = Config()
        self.assertEqual(config.get("nonexistent.key", "default"), "default")

    def test_security_profiles_have_secure_defaults(self):
        standard = get_security_profile("standard")
        enhanced = get_security_profile("enhanced")
        paranoid = get_security_profile("paranoid")

        self.assertEqual(standard["auto_lock_minutes"], 5)
        self.assertEqual(enhanced["clipboard_delivery_mode"], "memory_only")
        self.assertEqual(paranoid["auto_lock_minutes"], 1)
        self.assertEqual(paranoid["clipboard_security_level"], "paranoid")
        self.assertTrue(paranoid["panic_stealth_mode"])
        self.assertTrue(paranoid["panic_gesture_enabled"])
        self.assertTrue(paranoid["panic_fake_error"])

    def test_security_settings_validation_blocks_insecure_combinations(self):
        validation = validate_security_settings(
            {
                "security_profile": "paranoid",
                "clipboard_security_level": "paranoid",
                "clipboard_delivery_mode": "system",
                "auto_lock_minutes": 999,
            }
        )

        self.assertFalse(validation.valid)
        self.assertIn("Для параноидального уровня нужен режим буфера обмена «только память»", validation.errors)
        self.assertEqual(validation.settings["auto_lock_minutes"], 480)

    def test_apply_security_profile_updates_and_validates_settings(self):
        config = Config()

        updated = config.apply_security_profile("enhanced")

        self.assertEqual(updated["security_profile"], "enhanced")
        self.assertEqual(config.get("security.security_profile"), "enhanced")
        self.assertEqual(config.get("security.clipboard_delivery_mode"), "memory_only")
        self.assertEqual(config.get("security.activity_sensitivity"), "high")

    def test_apply_security_profile_helper_preserves_non_security_values(self):
        current = {"min_password_length": 16, "custom_flag": "keep"}

        updated = apply_security_profile(current, "standard")

        self.assertEqual(updated["security_profile"], "standard")
        self.assertEqual(updated["custom_flag"], "keep")


if __name__ == "__main__":
    unittest.main()