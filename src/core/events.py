from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

class EventType(Enum):
    ENTRY_ADDED = "entry_added"
    ENTRY_VIEWED = "entry_viewed"
    ENTRY_UPDATED = "entry_updated"
    ENTRY_DELETED = "entry_deleted"
    USER_LOGGED_IN = "user_logged_in"
    USER_LOGIN_FAILED = "user_login_failed"
    USER_LOGGED_OUT = "user_logged_out"
    PASSWORD_CHANGED = "password_changed"
    CLIPBOARD_COPIED = "clipboard_copied"
    CLIPBOARD_CLEARED = "clipboard_cleared"
    CLIPBOARD_ERROR = "clipboard_error"
    VAULT_UNLOCKED = "vault_unlocked"
    VAULT_LOCKED = "vault_locked"
    SETTINGS_CHANGED = "settings_changed"
    SEARCH_PERFORMED = "search_performed"
    APP_STARTED = "app_started"
    APP_SHUTDOWN = "app_shutdown"
    AUDIT_LOG_EXPORTED = "audit_log_exported"
    AUDIT_VERIFICATION_PASSED = "audit_verification_passed"
    AUDIT_VERIFICATION_FAILED = "audit_verification_failed"
    EXPORT_OPERATION_STARTED = "export_operation_started"
    EXPORT_OPERATION_COMPLETED = "export_operation_completed"
    EXPORT_OPERATION_FAILED = "export_operation_failed"
    IMPORT_OPERATION_STARTED = "import_operation_started"
    IMPORT_OPERATION_COMPLETED = "import_operation_completed"
    IMPORT_OPERATION_FAILED = "import_operation_failed"
    SHARE_CREATED = "share_created"
    SHARE_IMPORTED = "share_imported"
    SHARE_REVOKED = "share_revoked"
    KEY_EXCHANGE_CREATED = "key_exchange_created"
    KEY_EXCHANGE_IMPORTED = "key_exchange_imported"
    PANIC_MODE_ACTIVATED = "panic_mode_activated"
    PANIC_MODE_DEACTIVATED = "panic_mode_deactivated"
    TOTP_CODE_GENERATED = "totp_code_generated"
    TOTP_VERIFICATION_PERFORMED = "totp_verification_performed"


class Event:
    def __init__(self, event_type: EventType, data: Any):
        self.type = event_type
        self.data = data
        self.timestamp = datetime.now()


class EventBus:
    def __init__(self):
        self._subscribers: Dict[EventType, List[Callable]] = {}

    def subscribe(self, event_type: EventType, callback: Callable):
        self._subscribers.setdefault(event_type, []).append(callback)

    def unsubscribe(self, event_type: EventType, callback: Callable):
        callbacks = self._subscribers.get(event_type, [])
        if callback in callbacks:
            callbacks.remove(callback)

    def publish(self, event: Event):
        for callback in self._subscribers.get(event.type, []):
            callback(event)


event_bus = EventBus()

class AuditLoggerStub:
    def __init__(self, bus: EventBus):
        self.event_bus = bus
        events = [
            EventType.ENTRY_ADDED,
            EventType.ENTRY_UPDATED,
            EventType.ENTRY_DELETED,
            EventType.USER_LOGGED_IN,
            EventType.USER_LOGGED_OUT,
        ]
        for event_type in events:
            self.event_bus.subscribe(event_type, self._log_event)

    def _log_event(self, event: Event):
        print(f"[AUDIT] {event.timestamp} - {event.type.value}: {event.data}")