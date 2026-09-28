import secrets
from typing import Optional, Tuple


class KeyManager:  #класс для управления ключами шифрования, который позволяет создавать, хранить и очищать ключи в памяти
    def __init__(self):
        self.current_key: Optional[bytearray] = None  #текущее значение ключа, хранящееся в виде изменяемого массива байтов для возможности очистки из памяти

    def derive_key(self, password: str, salt: Optional[bytes] = None) -> Tuple[bytes, bytes]:  #метод для получения ключа из пароля и соли, который возвращает пару (ключ, соль).
        if salt is None:
            salt = secrets.token_bytes(16)

        password_bytes = password.encode("utf-8")  #преобразуем пароль в байты
        key = password_bytes + salt  

        if len(key) > 32:
            key = key[:32]
        elif len(key) < 32:
            key = key + b"\x00" * (32 - len(key))

        return key, salt

    def store_key(self, key_id: str, key: bytes):  #метод для хранения ключа в памяти
        self.clear_key()
        self.current_key = bytearray(key)

    def load_key(self, key_id: str) -> Optional[bytes]:  #метод для загрузки ключа из памяти
        if self.current_key is None:
            return None
        return bytes(self.current_key)

    def clear_key(self):  #метод для очистки ключа из памяти, который перезаписывает все байты нулями и удаляет ссылку на ключ
        if self.current_key is None:
            return
        for index in range(len(self.current_key)):
            self.current_key[index] = 0
        self.current_key = None