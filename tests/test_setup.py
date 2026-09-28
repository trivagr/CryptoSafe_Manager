import unittest
import sys
import os
import tempfile
from datetime import datetime

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.core.config import Config
from src.database.db import Database
from src.database.models import VaultEntry


class TestSetup(
    unittest.TestCase):  # класс для тестирования базовой настройки приложения, включая конфигурацию и базу данных
    def setUp(self):
        # временные файлы
        self.temp_config = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False)
        self.temp_config.close()
        self.temp_db = tempfile.NamedTemporaryFile(suffix='.db', delete=False)
        self.temp_db.close()

    def tearDown(self):
        # удаляем временные файлы
        try:
            os.unlink(self.temp_config.name)
            os.unlink(self.temp_db.name)
        except:
            pass

    def test_config_creation(self):
        config = Config()
        self.assertIsNotNone(config.get('database.path'))

    def test_database_creation(self):  # тест для проверки создания базы данных и добавления записи
        db = Database(self.temp_db.name)

        # создаем запись с датами!
        now = datetime.now()
        entry = VaultEntry(
            title="Test",
            username="user",
            encrypted_password=b"test",
            url="",
            notes="",
            created_at=now,
            updated_at=now,
            tags=""
        )

        entry_id = db.add_entry(entry)
        self.assertGreater(entry_id, 0)

        # проверяем что запись сохранилась
        saved = db.get_entry(entry_id)
        self.assertEqual(saved.title, "Test")

    def test_config_save_load(self):  # тест для проверки сохранения и загрузки конфигурации
        config = Config()
        config.set('test.key', 'test_value')
        config.save()

        # создаем новый конфиг, он должен загрузить сохраненный
        config2 = Config()
        self.assertEqual(config2.get('test.key'), 'test_value')


if __name__ == '__main__':
    unittest.main()