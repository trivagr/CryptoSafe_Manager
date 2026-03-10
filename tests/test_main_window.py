import unittest
import tkinter as tk
from src.gui.main_window import MainWindow

class TestMainWindowIntegration(unittest.TestCase):
    def setUp(self):
        # Создаём корневое окно Tkinter
        self.root = tk.Tk()
        # Подавляем отображение окна
        self.root.withdraw()

    def tearDown(self):
        # Закрываем окно после теста
        self.root.destroy()

    def test_main_window_launches(self):
        """
        Проверяем, что MainWindow создаётся и отображается без ошибок
        """
        try:
            window = MainWindow()
            # Обновляем UI один раз, чтобы убедиться, что нет ошибок
            window.update()
            window.destroy()
        except Exception as e:
            self.fail(f"MainWindow failed to launch: {e}")

if __name__ == "__main__":
    unittest.main()