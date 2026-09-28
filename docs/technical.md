# Техническая документация CryptoSafe Manager

Документ предназначен для защиты проекта и описывает внутреннюю структуру приложения, ключевые модули, тестирование, покрытие, сборку и финальные артефакты Sprint 8.

## 1. Назначение проекта

CryptoSafe Manager — локальный password manager с GUI, SQLite-хранилищем, мастер-паролем, шифрованием записей, безопасным clipboard, аудитом, импортом/экспортом, secure sharing, panic mode и desktop packaging.

Основной принцип: GUI вызывает сервисы, сервисы работают с БД и событиями, чувствительные данные не должны храниться в открытом виде дольше необходимого.

## 2. Точка входа

Главная точка запуска:

```text
run.py
```

Что делает `run.py`:

- добавляет корень проекта в `sys.path`;
- импортирует `MainWindow`;
- поддерживает специальные memory dump режимы для тестов Sprint 4;
- запускает GUI-приложение;
- выводит понятную ошибку при проблемах старта.

## 3. Структура проекта

Основные каталоги:

- `src/core/`: бизнес-логика и сервисы безопасности.
- `src/database/`: SQLite-слой, миграции, модели данных.
- `src/gui/`: Tkinter GUI и пользовательские окна.
- `src/gui/widgets/`: переиспользуемые виджеты.
- `tests/`: unit, integration, performance, memory и integrity-тесты.
- `tests/report/`: отчет тестирования Sprint 8.
- `docs/`: пользовательская и техническая документация.

## 4. Основные core-модули

### Crypto

Путь:

```text
src/core/crypto/
```

Отвечает за:

- проверку мастер-пароля;
- derivation ключей;
- хранение key metadata;
- проверку сложности пароля;
- legacy-шифрование для совместимости со старыми записями.

Ключевые файлы:

- `authentication.py`
- `key_derivation.py`
- `key_storage.py`
- `password_validator.py`
- `legacy_encryption.py`

### Vault

Путь:

```text
src/core/vault/
```

Отвечает за:

- AES-256-GCM шифрование записей;
- CRUD-операции через `EntryManager`;
- генерацию паролей;
- поиск и индексацию записей.

Ключевые файлы:

- `encryption_service.py`
- `entry_manager.py`
- `password_generator.py`
- `search_index.py`

### Clipboard

Путь:

```text
src/core/clipboard/
```

Отвечает за:

- копирование секретов;
- auto-clear;
- мониторинг системного clipboard;
- memory-only режим;
- platform adapters для Windows/macOS/Linux;
- события и предупреждения безопасности.

Ключевые файлы:

- `clipboard_service.py`
- `clipboard_monitor.py`
- `platform_adapter.py`

### Audit

Путь:

```text
src/core/audit/
```

Отвечает за:

- append-only audit log;
- hash chain;
- подписи записей;
- проверку целостности;
- экспорт журнала;
- async logging для некритичных событий.

Ключевые файлы:

- `audit_logger.py`
- `log_signer.py`
- `log_verifier.py`
- `log_formatters.py`

### Import/export и sharing

Путь:

```text
src/core/import_export/
```

Отвечает за:

- encrypted JSON export/import;
- Bitwarden encrypted JSON;
- импорт password manager форматов;
- безопасную передачу отдельной записи;
- RSA/ECC public-key sharing;
- QR/key exchange.

Ключевые файлы:

- `exporter.py`
- `importer.py`
- `sharing_service.py`
- `key_exchange.py`
- `crypto.py`
- `formats/password_manager.py`

### Security

Путь:

```text
src/core/security/
```

Отвечает за:

- memory guard;
- activity monitor;
- panic mode;
- platform security checks;
- side-channel helpers;
- memory dump проверки.

Ключевые файлы:

- `memory_guard.py`
- `activity_monitor.py`
- `panic_mode.py`
- `platform_security.py`
- `side_channel_protection.py`
- `memory_dump_probe.py`

## 5. База данных

Путь:

```text
src/database/db.py
```

Используется SQLite. Основные сущности:

- `vault_entries`: записи vault.
- `audit_log`: журнал аудита.
- `settings`: настройки приложения.
- `key_store`: параметры мастер-пароля и ключей.
- `shared_entries`: история secure sharing.
- `contacts`: публичные ключи контактов.
- `import_export_history`: история операций импорта/экспорта.

Схема мигрируется через `PRAGMA user_version`. Текущие тесты проверяют миграции до актуальной версии.

## 6. EventBus

Путь:

```text
src/core/events.py
```

EventBus связывает модули без прямой жесткой зависимости GUI от аудита или сервисов друг от друга.

Примеры событий:

- `ENTRY_ADDED`
- `ENTRY_UPDATED`
- `CLIPBOARD_COPIED`
- `VAULT_UNLOCKED`
- `EXPORT_OPERATION_COMPLETED`
- `SHARE_CREATED`
- `PANIC_MODE_ACTIVATED`

В Sprint 8 циклический импорт `events -> audit -> events` был убран и закрыт integrity-тестом.

## 7. GUI

Путь:

```text
src/gui/main_window.py
```

GUI реализован на Tkinter. Основные возможности:

- выбор vault до ввода мастер-пароля;
- lock/unlock;
- CRUD записей;
- поиск и фильтры;
- clipboard actions;
- audit viewer;
- import/export dialogs;
- share и QR/key exchange;
- settings/security profiles;
- tray integration;
- panic mode.

Для сложных форм используется прокрутка, чтобы кнопки были доступны на экранах с разным масштабированием.

## 8. Тестирование

Основной запуск:

```powershell
python -m pytest
```

Результат последнего Sprint 8 прогона:

- 383 теста пройдено;
- 10 slow/stress тестов исключены из основного запуска;
- время coverage-запуска по JUnit: 30.884с.

Slow/stress запуск:

```powershell
python -m pytest -m slow
```

Результат:

- 10 тестов пройдено;
- проверяются performance, memory dump и stress-сценарии.

Coverage:

```powershell
python -m pytest --cov=src --cov-report=term --cov-report=html:tests/report/html --junitxml=tests/report/junit.xml
```

Результат:

- coverage: 83%;
- HTML report: `tests/report/html/index.html`;
- JUnit report: `tests/report/junit.xml`;
- summary: `tests/report/summary.md`.

## 9. Integrity checks Sprint 8

Файл:

```text
tests/test_project_integrity.py
```

Проверяет:

- отсутствие технических маркеров в `src`;
- отсутствие циклических импортов между модулями `src`.

Этот тест закрывает часть INT-требований Sprint 8 и защищает проект от регрессий перед сдачей.

## 10. Packaging

Spec-файл:

```text
cryptosafe-manager.spec
```

Команда сборки:

```powershell
python -m PyInstaller cryptosafe-manager.spec --noconfirm --clean
```

Результат:

```text
dist/CryptoSafe Manager/CryptoSafe Manager.exe
```

ZIP для сдачи:

```text
dist/CryptoSafe Manager.zip
```

Передавать нужно весь каталог сборки или ZIP, а не только `.exe`, потому что PyInstaller one-folder сборка хранит зависимости рядом в `_internal`.

## 11. Что показывать на защите

Минимальный технический маршрут:

1. Запуск `python run.py`.
2. Выбор vault.
3. Вход по мастер-паролю.
4. Добавление записи.
5. Копирование пароля и auto-clear clipboard.
6. Журнал аудита и проверка целостности.
7. Encrypted export/import.
8. Bitwarden encrypted export/import.
9. Share выбранной записи.
10. QR/key exchange.
11. Panic mode.
12. `python -m pytest`.
13. Coverage report из `tests/report/html/index.html`.
14. PyInstaller exe из `dist/CryptoSafe Manager`.

## 12. Известные ограничения

- Некоторые platform-specific clipboard/tray возможности зависят от ОС и установленных backend-библиотек.
- Slow/stress тесты вынесены в отдельный marker, чтобы основной набор соответствовал лимиту времени Sprint 8.
- Plaintext export не является рекомендуемым сценарием и используется только для совместимости, когда пользователь явно это разрешает.