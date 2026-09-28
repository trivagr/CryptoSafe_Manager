from datetime import datetime, timedelta
from typing import Callable, Optional

from ..events import Event, EventType, event_bus
from ..state_manager import StateManager
from .key_derivation import KeyDerivation
from .key_storage import KeyStorage
from .password_validator import PasswordValidator


class AuthenticationError(Exception):
    pass


class AuthenticationService:
    CACHE_TTL_SECONDS = 3600

    def __init__(
        self,
        key_storage: KeyStorage,
        key_derivation: KeyDerivation,
        password_validator: PasswordValidator,
        state_manager: Optional[StateManager] = None,
    ):
        self.key_storage = key_storage
        self.key_derivation = key_derivation
        self.password_validator = password_validator
        self.state_manager = state_manager or StateManager()
        self._failed_attempts = 0
        self._locked_until: Optional[datetime] = None

    def is_initialized(self) -> bool:
        return self.key_storage.has_master_key()

    def register_master_password(self, password: str):
        is_valid, errors = self.password_validator.validate(password, strict=True)
        if not is_valid:
            raise AuthenticationError("; ".join(errors))

        auth_data = self.key_derivation.create_auth_hash(password)
        encryption_key, encryption_salt = self.key_derivation.derive_encryption_key(password)
        self.key_storage.store_metadata(
            auth_data["hash"],
            encryption_salt,
            self.key_derivation.export_params(),
        )
        self.key_storage.cache_active_key(encryption_key, ttl_seconds=self.CACHE_TTL_SECONDS)
        self.state_manager.set_key_cache_timeout(self.CACHE_TTL_SECONDS)
        self.state_manager.unlock()
        self.state_manager.reset_failed_attempts()
        event_bus.publish(Event(EventType.USER_LOGGED_IN, {"initialized": True}))

    def authenticate(self, password: str) -> bool:
        if self._is_locked_out():
            event_bus.publish(
                Event(
                    EventType.USER_LOGIN_FAILED,
                    {
                        "reason": "lockout_active",
                        "remaining_seconds": self.get_lockout_remaining_seconds(),
                    },
                )
            )
            return False

        metadata = self.key_storage.load_metadata()
        if metadata is None:
            raise AuthenticationError("Master password is not initialized")

        stored_key_derivation = KeyDerivation.from_params(metadata.params)

        if not stored_key_derivation.verify_auth_hash(password, metadata.auth_hash):
            self._register_failure()
            return False

        encryption_key = stored_key_derivation.derive_key_with_known_salt(password, metadata.encryption_salt)
        self.key_storage.cache_active_key(encryption_key, ttl_seconds=self.CACHE_TTL_SECONDS)
        self.state_manager.set_key_cache_timeout(self.CACHE_TTL_SECONDS)
        self.state_manager.unlock()
        self._failed_attempts = 0
        self._locked_until = None
        self.state_manager.reset_failed_attempts()
        event_bus.publish(Event(EventType.USER_LOGGED_IN, {"initialized": False}))
        return True

    def change_master_password(
        self,
        current_password: str,
        new_password: str,
        rotate_entries_callback: Optional[Callable[[bytes, bytes], None]] = None,
    ):
        metadata = self.key_storage.load_metadata()
        if metadata is None:
            raise AuthenticationError("Master password is not initialized")
        current_key_derivation = KeyDerivation.from_params(metadata.params)
        if not current_key_derivation.verify_auth_hash(current_password, metadata.auth_hash):
            self._register_failure()
            raise AuthenticationError("Current password is invalid")

        is_valid, errors = self.password_validator.validate(new_password, strict=True)
        if not is_valid:
            raise AuthenticationError("; ".join(errors))

        old_encryption_key = current_key_derivation.derive_key_with_known_salt(current_password, metadata.encryption_salt)
        auth_data = self.key_derivation.create_auth_hash(new_password)
        new_encryption_key, new_encryption_salt = self.key_derivation.derive_encryption_key(new_password)

        try:
            if rotate_entries_callback is not None:
                rotate_entries_callback(old_encryption_key, new_encryption_key)
            self.key_storage.store_metadata(
                auth_data["hash"],
                new_encryption_salt,
                self.key_derivation.export_params(),
            )
        except Exception as error:
            self.key_storage.cache_active_key(old_encryption_key, ttl_seconds=self.CACHE_TTL_SECONDS)
            raise AuthenticationError(f"Vault re-encryption failed: {error}") from error

        self.key_storage.cache_active_key(new_encryption_key, ttl_seconds=self.CACHE_TTL_SECONDS)
        self.state_manager.unlock()
        self._failed_attempts = 0
        self._locked_until = None
        self.state_manager.reset_failed_attempts()
        event_bus.publish(Event(EventType.PASSWORD_CHANGED, {"status": "success"}))

    def logout(self):
        event_bus.publish(Event(EventType.USER_LOGGED_OUT, {}))
        self.key_storage.clear_cached_key()
        self.state_manager.lock()

    def is_authenticated(self) -> bool:
        if self.key_storage.is_cache_expired():
            return False
        return self.state_manager.is_unlocked() and self.key_storage.get_cached_key() is not None

    def get_active_key(self) -> Optional[bytes]:
        return self.key_storage.get_cached_key()

    def get_lockout_remaining_seconds(self) -> int:
        if self._locked_until is None:
            return 0
        return max(0, int((self._locked_until - datetime.now()).total_seconds()))

    def load_password_policy(self) -> dict:
        policy = self.key_storage.database.get_setting("security.password_policy", default={})
        if isinstance(policy, dict):
            return policy
        return {}

    def save_password_policy(self, policy: dict):
        self.key_storage.database.set_setting("security.password_policy", policy)

    def _is_locked_out(self) -> bool:
        return self._locked_until is not None and datetime.now() < self._locked_until

    def _register_failure(self):
        self._failed_attempts += 1
        self.state_manager.register_failed_attempt()
        if self._failed_attempts <= 2:
            delay_seconds = 1
        elif self._failed_attempts <= 4:
            delay_seconds = 5
        else:
            delay_seconds = 30
        self._locked_until = datetime.now() + timedelta(seconds=delay_seconds)
        event_bus.publish(
            Event(
                EventType.USER_LOGIN_FAILED,
                {
                    "reason": "invalid_password",
                    "failed_attempts": self._failed_attempts,
                    "lockout_seconds": delay_seconds,
                },
            )
        )