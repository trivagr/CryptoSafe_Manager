import copy
from dataclasses import dataclass
from typing import Any

from .hotkeys import parse_windows_hotkey


SECURITY_PROFILE_ORDER = ("standard", "enhanced", "paranoid")


SECURITY_PROFILES: dict[str, dict[str, Any]] = {
    "standard": {
        "security_profile": "standard",
        "auto_lock_minutes": 5,
        "activity_sensitivity": "medium",
        "device_profile": "desktop",
        "key_cache_timeout_minutes": 60,
        "lock_on_focus_loss": True,
        "lock_on_minimize": True,
        "clipboard_timeout": 30,
        "clipboard_security_level": "basic",
        "clipboard_delivery_mode": "system",
        "clipboard_blocked_on_suspicious": False,
        "memory_locking_enabled": True,
        "panic_hotkey": "Ctrl+Shift+Esc",
        "panic_close_application": False,
        "panic_stealth_mode": False,
        "panic_gesture_enabled": True,
        "panic_fake_error": True,
        "panic_decoy_command": "",
        "panic_redirect_url": "",
    },
    "enhanced": {
        "security_profile": "enhanced",
        "auto_lock_minutes": 3,
        "activity_sensitivity": "high",
        "device_profile": "laptop",
        "key_cache_timeout_minutes": 30,
        "lock_on_focus_loss": True,
        "lock_on_minimize": True,
        "clipboard_timeout": 20,
        "clipboard_security_level": "advanced",
        "clipboard_delivery_mode": "memory_only",
        "clipboard_blocked_on_suspicious": True,
        "memory_locking_enabled": True,
        "panic_hotkey": "Ctrl+Shift+Esc",
        "panic_close_application": False,
        "panic_stealth_mode": False,
        "panic_gesture_enabled": True,
        "panic_fake_error": True,
        "panic_decoy_command": "",
        "panic_redirect_url": "",
    },
    "paranoid": {
        "security_profile": "paranoid",
        "auto_lock_minutes": 1,
        "activity_sensitivity": "high",
        "device_profile": "laptop",
        "key_cache_timeout_minutes": 5,
        "lock_on_focus_loss": True,
        "lock_on_minimize": True,
        "clipboard_timeout": 10,
        "clipboard_security_level": "paranoid",
        "clipboard_delivery_mode": "memory_only",
        "clipboard_blocked_on_suspicious": True,
        "memory_locking_enabled": True,
        "panic_hotkey": "Ctrl+Shift+Esc",
        "panic_close_application": False,
        "panic_stealth_mode": True,
        "panic_gesture_enabled": True,
        "panic_fake_error": True,
        "panic_decoy_command": "",
        "panic_redirect_url": "",
    },
}


@dataclass
class SecuritySettingsValidation:
    valid: bool
    settings: dict[str, Any]
    warnings: list[str]
    errors: list[str]


def get_security_profile(profile_name: str) -> dict[str, Any]:
    normalized = str(profile_name or "standard").strip().lower()
    if normalized not in SECURITY_PROFILES:
        normalized = "standard"
    return copy.deepcopy(SECURITY_PROFILES[normalized])


def explain_security_profile(profile_name: str) -> str:
    normalized = str(profile_name or "standard").strip().lower()
    if normalized == "paranoid":
        return "Параноидальный: максимум защиты, короткие таймауты, буфер обмена только в памяти и скрытый паник-режим."
    if normalized == "enhanced":
        return "Усиленный: повышенная защита, буфер обмена только в памяти и более строгая автоблокировка."
    return "Стандартный: сбалансированный режим с безопасными настройками по умолчанию."


def apply_security_profile(current_settings: dict[str, Any], profile_name: str) -> dict[str, Any]:
    updated = copy.deepcopy(current_settings)
    updated.update(get_security_profile(profile_name))
    validation = validate_security_settings(updated)
    if not validation.valid:
        raise ValueError("; ".join(validation.errors))
    return validation.settings


def validate_security_settings(settings: dict[str, Any]) -> SecuritySettingsValidation:
    normalized = copy.deepcopy(settings)
    warnings: list[str] = []
    errors: list[str] = []

    profile = str(normalized.get("security_profile", "standard")).strip().lower()
    if profile not in SECURITY_PROFILES:
        errors.append("Неизвестный профиль безопасности")
        profile = "standard"
    normalized["security_profile"] = profile

    normalized["auto_lock_minutes"] = _clamp_int(normalized.get("auto_lock_minutes", 5), 1, 8 * 60)
    normalized["key_cache_timeout_minutes"] = _clamp_int(normalized.get("key_cache_timeout_minutes", 60), 1, 8 * 60)
    normalized["clipboard_timeout"] = _clamp_int(normalized.get("clipboard_timeout", 30), 5, 300)

    sensitivity = str(normalized.get("activity_sensitivity", "medium")).strip().lower()
    if sensitivity not in {"low", "medium", "high"}:
        errors.append("Недопустимая чувствительность мониторинга активности")
        sensitivity = "medium"
    normalized["activity_sensitivity"] = sensitivity

    device_profile = str(normalized.get("device_profile", "desktop")).strip().lower()
    if device_profile not in {"desktop", "laptop"}:
        errors.append("Недопустимый профиль устройства")
        device_profile = "desktop"
    normalized["device_profile"] = device_profile

    delivery_mode = str(normalized.get("clipboard_delivery_mode", "system")).strip().lower()
    if delivery_mode not in {"system", "memory_only"}:
        errors.append("Недопустимый режим доставки буфера обмена")
        delivery_mode = "system"
    normalized["clipboard_delivery_mode"] = delivery_mode

    clipboard_level = str(normalized.get("clipboard_security_level", "basic")).strip().lower()
    if clipboard_level not in {"basic", "advanced", "paranoid"}:
        errors.append("Недопустимый уровень защиты буфера обмена")
        clipboard_level = "basic"
    normalized["clipboard_security_level"] = clipboard_level

    for key in (
        "lock_on_focus_loss",
        "lock_on_minimize",
        "clipboard_blocked_on_suspicious",
        "memory_locking_enabled",
        "panic_close_application",
        "panic_stealth_mode",
        "panic_gesture_enabled",
        "panic_fake_error",
    ):
        normalized[key] = bool(normalized.get(key, False))

    normalized["panic_decoy_command"] = str(normalized.get("panic_decoy_command", "") or "").strip()
    normalized["panic_redirect_url"] = str(normalized.get("panic_redirect_url", "") or "").strip()
    normalized["panic_hotkey"] = str(normalized.get("panic_hotkey", "Ctrl+Shift+Esc") or "Ctrl+Shift+Esc").strip()
    try:
        parse_windows_hotkey(normalized["panic_hotkey"])
    except ValueError:
        errors.append("Недопустимая горячая клавиша паник-режима")
        normalized["panic_hotkey"] = "Ctrl+Shift+Esc"

    if clipboard_level == "paranoid" and delivery_mode != "memory_only":
        errors.append("Для параноидального уровня нужен режим буфера обмена «только память»")
    if normalized["auto_lock_minutes"] > 30:
        warnings.append("Таймаут автоблокировки длиннее безопасного значения по умолчанию")
    if not normalized["lock_on_focus_loss"]:
        warnings.append("Блокировка при потере фокуса отключена")
    if not normalized["memory_locking_enabled"]:
        warnings.append("Блокировка памяти отключена")

    return SecuritySettingsValidation(valid=not errors, settings=normalized, warnings=warnings, errors=errors)


def _clamp_int(value: Any, minimum: int, maximum: int) -> int:
    try:
        selected = int(value)
    except (TypeError, ValueError):
        selected = minimum
    return min(max(selected, minimum), maximum)