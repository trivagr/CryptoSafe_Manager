import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from src.gui.main_window import MainWindow
except ImportError as error:
    print("=" * 50)
    print("ОШИБКА: не удалось импортировать модули")
    print("=" * 50)
    print(f"Ошибка: {error}")
    print("\nУбедитесь, что файл существует:")
    print("  src/gui/main_window.py")
    sys.exit(1)


if __name__ == "__main__":
    if os.environ.get("CRYPTOSAFE_RUN_MEMORY_DUMP_TEST") == "1":
        from tests.test_run_memory_dump import run_memory_dump_mode

        run_memory_dump_mode()
        sys.exit(0)
    if os.environ.get("CRYPTOSAFE_SECURITY_MEMORY_DUMP_TEST") == "1":
        from src.core.security.memory_dump_probe import run_security_memory_dump_mode

        run_security_memory_dump_mode()
        sys.exit(0)

    print("=" * 50)
    print("CryptoSafe Manager")
    print("=" * 50)

    try:
        app = MainWindow()
        app.run()
    except Exception as error:
        print(f"\nОшибка: {error}")
        import traceback

        traceback.print_exc()
        input("\nНажмите Enter для выхода...")