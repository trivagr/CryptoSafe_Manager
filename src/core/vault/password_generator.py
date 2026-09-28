import secrets
import string
from collections import deque
from dataclasses import dataclass
from typing import Deque, List

AMBIGUOUS_CHARACTERS = {"l", "I", "1", "0", "O"}
SYMBOLS = "!@#$%^&*"  # набор символов для генерации паролей


@dataclass
class PasswordGeneratorOptions:  # класс для хранения параметров генерации пароля
    length: int = 16
    include_uppercase: bool = True
    include_lowercase: bool = True
    include_digits: bool = True
    include_symbols: bool = True
    exclude_ambiguous: bool = False


class PasswordGenerator:  # класс для генерации паролей на основе заданных параметров
    def __init__(self, history_limit: int = 20):
        self.history_limit = history_limit
        self._history: Deque[str] = deque(maxlen=history_limit)

    def generate(self, options: PasswordGeneratorOptions | None = None) -> str:  # метод для генерации пароля
        options = options or PasswordGeneratorOptions()  # если параметры не переданы, используются значения по умолчанию
        length = max(8, min(64, int(options.length)))  # ограничение длины пароля от 8 до 64 символов

        charsets = self._build_charsets(options)  # построение списка наборов символов на основе выбранных параметров
        if not charsets:
            raise ValueError("At least one character set must be enabled")

        if length < len(charsets):
            raise ValueError("Password length is too short for the selected character sets")

        for _ in range(100):
            password = self._generate_candidate(length,
                                                charsets)  # генерация кандидата на пароль и проверка его на уникальность и достаточную силу
            if password not in self._history and self.is_strong_enough(password):
                self._history.append(password)
                return password

        raise RuntimeError("Unable to generate a unique strong password with the provided options")

    def is_strong_enough(self,
                         password: str) -> bool:  # метод для оценки силы пароля на основе наличия различных типов символов и разнообразия символов
        if len(password) < 12:
            return False

        score = 0  # начальный балл
        # проверка наличия различных типов символов и разнообразия символов для увеличения балла
        if any(char.islower() for char in password):
            score += 1
        if any(char.isupper() for char in password):
            score += 1
        if any(char.isdigit() for char in password):
            score += 1
        if any(char in SYMBOLS for char in password):
            score += 1
        if len(set(password)) >= max(8, len(password) // 2):
            score += 1

        return score >= 4

    def recent_passwords(self) -> List[str]:  # метод для получения списка недавно сгенерированных паролей
        return list(self._history)

    def _build_charsets(self, options: PasswordGeneratorOptions) -> List[
        str]:  # метод для построения списка наборов символов на основе выбранных параметров
        charsets: List[str] = []
        if options.include_uppercase:
            charsets.append(self._filter_ambiguous(string.ascii_uppercase, options.exclude_ambiguous))
        if options.include_lowercase:
            charsets.append(self._filter_ambiguous(string.ascii_lowercase, options.exclude_ambiguous))
        if options.include_digits:
            charsets.append(self._filter_ambiguous(string.digits, options.exclude_ambiguous))
        if options.include_symbols:
            charsets.append(self._filter_ambiguous(SYMBOLS, options.exclude_ambiguous))
        return [charset for charset in charsets if charset]

    def _filter_ambiguous(self, charset: str, exclude_ambiguous: bool) -> str:  # метод для фильтрации набора символов
        if not exclude_ambiguous:
            return charset
        return "".join(char for char in charset if char not in AMBIGUOUS_CHARACTERS)

    def _generate_candidate(self, length: int, charsets: List[str]) -> str:  # метод для генерации кандидата на пароль
        required_characters = [secrets.choice(charset) for charset in charsets]
        all_characters = "".join(charsets)
        remaining = [secrets.choice(all_characters) for _ in range(length - len(
            required_characters))]  # заполнение оставшихся символов случайными символами из всех выбранных наборов
        password_chars = required_characters + remaining

        for index in range(len(password_chars) - 1, 0, -1):
            swap_index = secrets.randbelow(index + 1)
            password_chars[index], password_chars[swap_index] = password_chars[swap_index], password_chars[index]

        return "".join(password_chars)