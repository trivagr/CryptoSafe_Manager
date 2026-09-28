import base64
import hashlib
import json
import os
import queue
import threading
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .log_signer import AuditLogSigner
from .log_verifier import AuditLogVerifier


class AuditTimeSource:
    """UTC clock wrapper that records the source used for audit timestamps."""

    name = "system_utc_clock"

    def now(self) -> datetime:
        return datetime.now(timezone.utc)

    def metadata(self) -> Dict[str, Any]:
        checked_at = self.now().isoformat().replace("+00:00", "Z")
        return {
            "name": self.name,
            "timezone": "UTC",
            "synchronized": True,
            "reliable_source": "operating_system_clock",
            "checked_at": checked_at,
        }


class AuditLogger:
    def __init__(self, database, bus, key_provider: Optional[Callable[[], Optional[bytes]]] = None, config=None):
        self.database = database
        self.event_bus = bus
        self.key_provider = key_provider or (lambda: None)
        self.config = self._build_config(config)
        self.time_source = self.config.pop("time_source", AuditTimeSource())
        self.signer = AuditLogSigner(self.key_provider)
        self.verifier = AuditLogVerifier(self.database, self.signer)
        self._subscribed_types = []
        self._write_lock = threading.RLock()
        self._async_queue: "queue.Queue[Optional[Dict[str, Any]]]" = queue.Queue()
        self._async_stop_event = threading.Event()
        self._async_worker = None
        self._async_worker_error: Optional[Exception] = None
        self._last_retention_check_sequence = 0
        self._integration_hooks: Dict[str, Dict[str, Any]] = {}
        if hasattr(self.database, "set_audit_protection_callback"):
            self.database.set_audit_protection_callback(self._record_protection_violation)
        if hasattr(self.database, "set_audit_entry_data_decoder"):
            self.database.set_audit_entry_data_decoder(self._decrypt_entry_payload)
        self._start_async_worker()
        self._ensure_genesis_entry()
        self._subscribe_all_events()

    def close(self):
        self.flush()
        self._stop_async_worker()
        for event_type in self._subscribed_types:
            self.event_bus.unsubscribe(event_type, self._log_event)
        self._subscribed_types.clear()
        if hasattr(self.database, "set_audit_protection_callback"):
            self.database.set_audit_protection_callback(None)
        if hasattr(self.database, "set_audit_entry_data_decoder"):
            self.database.set_audit_entry_data_decoder(None)
        if hasattr(self.signer, "clear"):
            self.signer.clear()

    def flush(self):
        self._async_queue.join()
        if self._async_worker_error is not None:
            error = self._async_worker_error
            self._async_worker_error = None
            raise error

    def _subscribe_all_events(self):
        from ..events import EventType

        self._subscribed_types = list(EventType)
        for event_type in self._subscribed_types:
            self.event_bus.subscribe(event_type, self._log_event)

    def verify_integrity(self, start_sequence: int = 0, limit: Optional[int] = None) -> Dict[str, Any]:
        return self.verifier.verify(start_sequence=start_sequence, limit=limit)

    def register_integration_hook(
        self,
        name: str,
        callback: Callable[[Dict[str, Any]], None],
        *,
        event_types: Optional[list[str]] = None,
    ):
        hook_name = str(name or "").strip()
        if not hook_name:
            raise ValueError("Integration hook name cannot be empty")
        if not callable(callback):
            raise TypeError("Integration hook callback must be callable")
        normalized_event_types = None
        if event_types is not None:
            normalized_event_types = {str(event_type) for event_type in event_types}
        self._integration_hooks[hook_name] = {
            "callback": callback,
            "event_types": normalized_event_types,
        }

    def unregister_integration_hook(self, name: str):
        self._integration_hooks.pop(str(name or "").strip(), None)

    def _ensure_genesis_entry(self):
        if self._get_latest_entry() is not None:
            return
        if not self.key_provider():
            return
        self.log_event(
            event_type="system_genesis",
            severity="INFO",
            source="audit_logger",
            details={"message": "Audit log initialized"},
            user_id="system",
            entry_id=None,
        )

    def log_event(
        self,
        event_type: str,
        severity: str,
        source: str,
        details: Dict[str, Any],
        user_id: str = "local-user",
        entry_id: Optional[int] = None,
        *,
        force_sync: bool = False,
    ) -> int:
        if not self._has_active_audit_key():
            return 0
        if self._should_use_async_logging(event_type, severity, force_sync=force_sync):
            self._async_queue.put(
                {
                    "event_type": event_type,
                    "severity": severity,
                    "source": source,
                    "details": dict(details),
                    "user_id": user_id,
                    "entry_id": entry_id,
                }
            )
            return 0
        return self._write_entry(
            event_type=event_type,
            severity=severity,
            source=source,
            details=details,
            user_id=user_id,
            entry_id=entry_id,
            apply_retention=True,
        )

    def _has_active_audit_key(self) -> bool:
        try:
            return bool(self.key_provider())
        except Exception:
            return False

    def _write_entry(
        self,
        *,
        event_type: str,
        severity: str,
        source: str,
        details: Dict[str, Any],
        user_id: str,
        entry_id: Optional[int],
        apply_retention: bool,
    ) -> int:
        with self._write_lock:
            if event_type != "system_genesis" and self._get_latest_entry() is None:
                self._ensure_genesis_entry()
            previous_entry = self._get_latest_entry()
            previous_hash = previous_entry.entry_hash if previous_entry else "0" * 64
            sequence_number = (previous_entry.sequence_number if previous_entry else 0) + 1
            timestamp = self._utc_now()
            time_source = self._time_source_metadata()

            payload = {
                "timestamp": timestamp,
                "time_source": time_source,
                "event_type": event_type,
                "severity": severity,
                "user_id": user_id,
                "source": source,
                "entry_id": entry_id,
                "details": self._sanitize_details(details),
                "sequence_number": sequence_number,
                "previous_hash": previous_hash,
            }
            entry_data = json.dumps(payload, ensure_ascii=False, sort_keys=True)
            entry_hash = hashlib.sha256(entry_data.encode("utf-8")).hexdigest()
            signature = self.signer.sign_for_sequence(entry_data.encode("utf-8"), sequence_number)
            public_key = self.signer.public_key_for_sequence(sequence_number)
            algorithm = self.signer.algorithm_for_sequence(sequence_number)
            self.database.register_audit_public_key(algorithm, public_key)
            record_id = self.database.add_audit_log(
                action=event_type,
                event_type=event_type,
                timestamp=datetime.fromisoformat(timestamp.replace("Z", "+00:00")),
                severity=severity,
                user_id=user_id,
                source=source,
                entry_id=entry_id,
                details=json.dumps(payload["details"], ensure_ascii=False, sort_keys=True),
                previous_hash=previous_hash,
                entry_hash=entry_hash,
                entry_data=self._encrypt_entry_payload(entry_data),
                signature=signature,
                public_key=public_key,
                sequence_number=sequence_number,
            )
            if apply_retention:
                self._apply_retention_policy(sequence_number)
            self._notify_integration_hooks(
                {
                    "sequence_number": sequence_number,
                    "timestamp": timestamp,
                    "event_type": event_type,
                    "severity": severity,
                    "user_id": user_id,
                    "source": source,
                    "entry_id": entry_id,
                    "details": payload["details"],
                    "previous_hash": previous_hash,
                    "entry_hash": entry_hash,
                    "signature": signature,
                    "public_key": public_key,
                    "time_source": time_source,
                }
            )
            return record_id

    def _log_event(self, event):
        entry_id = None
        details: Dict[str, Any]
        if isinstance(event.data, dict):
            entry_id = event.data.get("id") or event.data.get("entry_id")
            details = dict(event.data)
        elif event.data is None:
            details = {}
        else:
            details = {"message": str(event.data)}

        self.log_event(
            event_type=event.type.value,
            severity=self._map_severity(event.type.value),
            source=self._map_source(event.type.value),
            details=details,
            entry_id=entry_id,
            force_sync=self._requires_immediate_persistence(event.type.value),
        )

    def _requires_immediate_persistence(self, event_type: str) -> bool:
        return event_type in {
            "user_logged_in",
            "user_logged_out",
            "entry_added",
            "entry_updated",
            "entry_deleted",
            "vault_locked",
            "vault_unlocked",
            "panic_mode_activated",
            "panic_mode_deactivated",
            "export_operation_completed",
            "import_operation_completed",
            "share_created",
            "share_imported",
            "key_exchange_created",
            "key_exchange_imported",
        }

    def _build_config(self, config: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        base_rotation_policy = {"enabled": True, "max_entries": 10000, "max_age_days": 365}
        if hasattr(self.database, "get_audit_retention_policy"):
            base_rotation_policy.update(self.database.get_audit_retention_policy())

        user_config = dict(config or {})
        user_rotation_policy = user_config.pop("rotation_policy", {}) or {}
        base_rotation_policy.update(user_rotation_policy)

        return {
            "async_logging_enabled": bool(user_config.pop("async_logging_enabled", True)),
            "rotation_policy": base_rotation_policy,
            **user_config,
        }

    def _should_use_async_logging(self, event_type: str, severity: str, *, force_sync: bool) -> bool:
        if force_sync or not self.config.get("async_logging_enabled", True):
            return False
        if event_type in {
            "system_genesis",
            "audit_log_archived",
            "audit_log_protection_triggered",
            "audit_verification_failed",
        }:
            return False
        if severity == "INFO":
            return True
        return event_type in {
            "settings_changed",
            "search_performed",
            "app_started",
            "app_shutdown",
            "user_logged_out",
        }

    def _start_async_worker(self):
        if not self.config.get("async_logging_enabled", True):
            return
        self._async_worker = threading.Thread(
            target=self._run_async_worker,
            name="audit-log-writer",
            daemon=True,
        )
        self._async_worker.start()

    def _stop_async_worker(self):
        if self._async_worker is None:
            return
        self._async_stop_event.set()
        self._async_queue.put(None)
        self._async_worker.join(timeout=2.0)
        self._async_worker = None

    def _run_async_worker(self):
        while not self._async_stop_event.is_set() or not self._async_queue.empty():
            try:
                payload = self._async_queue.get(timeout=0.1)
            except queue.Empty:
                continue
            try:
                if payload is None:
                    continue
                self._write_entry(
                    event_type=str(payload["event_type"]),
                    severity=str(payload["severity"]),
                    source=str(payload["source"]),
                    details=dict(payload["details"]),
                    user_id=str(payload["user_id"]),
                    entry_id=payload["entry_id"],
                    apply_retention=True,
                )
            except Exception as error:
                self._async_worker_error = error
            finally:
                self._async_queue.task_done()

    def _apply_retention_policy(self, current_sequence: int):
        rotation_policy = self.config.get("rotation_policy", {})
        if not rotation_policy.get("enabled", True):
            return
        if not hasattr(self.database, "archive_audit_logs"):
            return
        max_entries = int(rotation_policy.get("max_entries", 10000))
        if current_sequence <= max_entries:
            return
        check_interval = 1 if max_entries <= 100 else max(100, max_entries // 10)
        if current_sequence - self._last_retention_check_sequence < check_interval:
            return
        self._last_retention_check_sequence = current_sequence
        archive_result = self.database.archive_audit_logs(
            max_entries=max_entries,
            max_age_days=int(rotation_policy.get("max_age_days", 365)),
        )
        if not archive_result.get("archived"):
            return
        self._write_entry(
            event_type="audit_log_archived",
            severity="INFO",
            source="audit",
            details={
                "archive_id": archive_result.get("archive_id"),
                "entry_count": archive_result.get("entry_count"),
                "range_start_sequence": archive_result.get("range_start_sequence"),
                "range_end_sequence": archive_result.get("range_end_sequence"),
                "reason": archive_result.get("reason", "retention_policy"),
            },
            user_id="system",
            entry_id=None,
            apply_retention=False,
        )

    def _record_protection_violation(self, operation: str, details: Dict[str, Any]):
        payload = dict(details)
        payload["operation"] = operation
        if hasattr(self.database, "add_audit_security_event"):
            self.database.add_audit_security_event(
                "audit_log_protection_triggered",
                severity="CRITICAL",
                details=payload,
                related_sequence_number=payload.get("sequence_number"),
            )
        self._write_entry(
            event_type="audit_log_protection_triggered",
            severity="CRITICAL",
            source="audit_storage",
            details=payload,
            user_id="system",
            entry_id=None,
            apply_retention=False,
        )

    def _map_severity(self, event_type: str) -> str:
        if event_type in {"clipboard_error", "audit_verification_failed", "import_operation_failed"}:
            return "ERROR"
        if event_type in {"panic_mode_activated"}:
            return "CRITICAL"
        if event_type in {"user_login_failed", "settings_changed", "totp_verification_performed"}:
            return "WARN"
        if "failed" in event_type or "suspicious" in event_type:
            return "WARN"
        return "INFO"

    def _map_source(self, event_type: str) -> str:
        if event_type.startswith("clipboard_"):
            return "clipboard"
        if event_type.startswith("entry_"):
            return "vault"
        if event_type.startswith("user_"):
            return "authentication"
        if event_type.startswith("audit_"):
            return "audit"
        if event_type.startswith("search_"):
            return "vault_search"
        if event_type.startswith("settings_"):
            return "configuration"
        if event_type.startswith("app_"):
            return "application"
        if event_type.startswith("vault_"):
            return "system"
        if event_type.startswith("export_operation"):
            return "data_export"
        if event_type.startswith("import_operation"):
            return "data_import"
        if event_type.startswith("share_"):
            return "secure_sharing"
        if event_type.startswith("key_exchange_"):
            return "key_exchange"
        if event_type.startswith("panic_mode"):
            return "panic_mode"
        if event_type.startswith("totp_"):
            return "totp"
        return "application"

    def _sanitize_details(self, details: Dict[str, Any]) -> Dict[str, Any]:
        sanitized: Dict[str, Any] = {}
        for key, value in details.items():
            normalized_key = str(key).lower()
            if any(marker in normalized_key for marker in ("password", "secret", "key")):
                sanitized[key] = "[REDACTED]"
                continue
            if normalized_key in {"query", "username", "email", "ip", "search_text"}:
                sanitized[key] = self._hash_value(value)
                continue
            if isinstance(value, dict):
                sanitized[key] = self._sanitize_details(value)
                continue
            if isinstance(value, list):
                sanitized[key] = [self._sanitize_list_value(item) for item in value]
                continue
            sanitized[key] = value
        return sanitized

    def _sanitize_list_value(self, value: Any):
        if isinstance(value, dict):
            return self._sanitize_details(value)
        return value

    def _hash_value(self, value: Any) -> str:
        return hashlib.sha256(str(value).encode("utf-8")).hexdigest()

    def _utc_now(self) -> str:
        return self.time_source.now().isoformat().replace("+00:00", "Z")

    def _time_source_metadata(self) -> Dict[str, Any]:
        if hasattr(self.time_source, "metadata"):
            return dict(self.time_source.metadata())
        return {
            "name": "system_utc_clock",
            "timezone": "UTC",
            "synchronized": True,
            "reliable_source": "operating_system_clock",
        }

    def _notify_integration_hooks(self, payload: Dict[str, Any]):
        if not self._integration_hooks:
            return
        event_type = str(payload.get("event_type", ""))
        for hook_name, hook in list(self._integration_hooks.items()):
            event_types = hook.get("event_types")
            if event_types is not None and event_type not in event_types:
                continue
            try:
                hook["callback"](dict(payload))
            except Exception as error:
                if hasattr(self.database, "add_audit_security_event"):
                    self.database.add_audit_security_event(
                        "audit_integration_hook_failed",
                        severity="WARN",
                        details={
                            "hook": hook_name,
                            "event_type": event_type,
                            "message": str(error),
                        },
                        related_sequence_number=payload.get("sequence_number"),
                    )

    def _encrypt_entry_payload(self, entry_data: str) -> str:
        storage_key = self.signer.derive_storage_key()
        return self._encrypt_entry_payload_with_key(entry_data, storage_key)

    def _encrypt_entry_payload_with_key(self, entry_data: str, storage_key: bytes) -> str:
        nonce = os.urandom(12)
        ciphertext = nonce + AESGCM(storage_key).encrypt(nonce, entry_data.encode("utf-8"), None)
        envelope = {
            "encrypted": True,
            "algorithm": "AES-256-GCM",
            "key_context": "audit-storage-v1",
            "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        }
        return json.dumps(envelope, ensure_ascii=False, sort_keys=True)

    def _decrypt_entry_payload(self, raw_value: Any) -> str:
        storage_key = self.signer.derive_storage_key()
        return self._decrypt_entry_payload_with_key(raw_value, storage_key)

    def _decrypt_entry_payload_with_key(self, raw_value: Any, storage_key: bytes) -> str:
        if raw_value is None:
            return ""
        if isinstance(raw_value, bytes):
            raw_text = raw_value.decode("utf-8")
        else:
            raw_text = str(raw_value)
        try:
            parsed = json.loads(raw_text)
        except (TypeError, json.JSONDecodeError):
            return raw_text
        if not isinstance(parsed, dict) or not parsed.get("encrypted"):
            return raw_text
        if parsed.get("key_context") != "audit-storage-v1":
            return raw_text
        ciphertext = parsed.get("ciphertext", "")
        if not ciphertext:
            return raw_text
        encrypted_payload = base64.b64decode(ciphertext)
        nonce = encrypted_payload[:12]
        payload = encrypted_payload[12:]
        plaintext = AESGCM(storage_key).decrypt(nonce, payload, None)
        return plaintext.decode("utf-8")

    def reencrypt_entry_payloads(self, old_active_key: bytes, new_active_key: bytes, *, progress_callback=None, pause_event=None) -> int:
        old_storage_key = self._derive_storage_key_from_active_key(old_active_key)
        new_storage_key = self._derive_storage_key_from_active_key(new_active_key)

        def transform(raw_value: Any) -> str:
            try:
                plaintext = self._decrypt_entry_payload_with_key(raw_value, old_storage_key)
            except Exception:
                return raw_value.decode("utf-8") if isinstance(raw_value, bytes) else str(raw_value or "")
            return self._encrypt_entry_payload_with_key(plaintext, new_storage_key)

        if not hasattr(self.database, "reencrypt_audit_entry_payloads"):
            return 0
        return self.database.reencrypt_audit_entry_payloads(
            transform,
            progress_callback=progress_callback,
            pause_event=pause_event,
        )

    def _derive_storage_key_from_active_key(self, active_key: bytes) -> bytes:
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=self.signer.STORAGE_CONTEXT,
        )
        return hkdf.derive(active_key)

    def _get_latest_entry(self):
        if hasattr(self.database, "get_latest_audit_log"):
            return self.database.get_latest_audit_log()
        rows = self.database.get_audit_log_chain(limit=1)
        if not rows:
            return None
        return rows[-1]