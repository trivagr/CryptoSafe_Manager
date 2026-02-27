# CryptoSafe_Manager
CryptoSafe Manager — безопасное хранилище паролей и конфиденциальных данных с модульной архитектурой.

| Спринт | Цель                                                                                                                                               |
|--------|----------------------------------------------------------------------------------------------------------------------------------------------------|
| Спринт 1 | [Основа - защищенная база данных и каркас GUI](https://github.com/unklefck/applied_crypto_course/blob/main/Semester%201/Project/sprint1.md)        |
| Спринт 2 | [Мастер пароль и управление ключами](https://github.com/unklefck/applied_crypto_course/blob/main/Semester%201/Project/sprint2.md)                  |
| Спринт 3 | [Основные операции с хранилищем (CRUD)](https://github.com/unklefck/applied_crypto_course/blob/main/Semester%201/Project/sprint3.md)               |
| Спринт 4 | [Защищенный буфер обмена с автоочисткой](https://github.com/unklefck/applied_crypto_course/blob/main/Semester%201/Project/sprint4.md)              |
| Спринт 5 | [Аудит-логи и защита целостности](https://github.com/unklefck/applied_crypto_course/blob/main/Semester%201/Project/sprint5.md)                     |
| Спринт 6 | [Импорт/Экспорт и безопасный обмен](https://github.com/unklefck/applied_crypto_course/blob/main/Semester%201/Project/sprint6.md)                   |
| Спринт 7 | [Усиление защиты и улучшение UX](https://github.com/unklefck/applied_crypto_course/blob/main/Semester%201/Project/sprint7.md)                      |
| Спринт 8 | [Финальная интеграция, тестирование и документация](https://github.com/unklefck/applied_crypto_course/blob/main/Semester%201/Project/sprint8.md)   |

## ⚙️ Настройка проекта и виртуального окружения

1. **Клонируем репозиторий проекта:**

```bash
git clone https://github.com/<username>/CryptoSafe_Manager.git
cd CryptoSafe_Manager
python -m venv .venv
.venv\Scripts\Activate.ps1 -- Windows
source .venv/bin/activate -- Linux/MacOs
pip install -r requirements.txt
python src/gui/main_window.py

Архитектура:
+-------------------------+
|        GUI (View)       |
|-------------------------|
| main_window.py, widgets |
+-----------+-------------+
            |
            v
+-------------------------+
|  Core (Controller/Logic)|
|-------------------------|
| crypto/                 |
| config.py               |
| events.py               |
| state_manager.py        |
+-----------+-------------+
            |
            v
+-------------------------+
|       Database (Model)  |
|-------------------------|
| db.py                   |
| models.py               |
+-------------------------+
