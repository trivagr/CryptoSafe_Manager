import base64
import gzip
import hmac
import json
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, Optional

from ..events import Event, EventType
from .crypto import checksum, derive_password_key, encrypt_aes_gcm, encrypt_with_public_key, new_salt_and_nonce, wipe_bytes
from .models import ExportOptions
from .formats import BitwardenEncryptedJSONFormat, BitwardenJSONFormat, CSVVaultFormat, LastPassCSVFormat, NativeJSONFormat


class VaultExporter:
    def __init__(self, entry_manager, database=None, event_bus=None):
        self.entry_manager = entry_manager
        self.database = database
        self.event_bus = event_bus

    def get_entries_for_export(self, options: Optional[ExportOptions] = None) -> list[Dict[str, Any]]:
        selected_options = options or ExportOptions()
        if selected_options.entry_ids:
            return [self.entry_manager.get_entry(int(entry_id)) for entry_id in selected_options.entry_ids]
        return list(self.entry_manager.get_all_entries())

    def filter_entry_fields(self, entries: Iterable[Dict[str, Any]], include_fields: Optional[list[str]]) -> list[Dict[str, Any]]:
        if not include_fields:
            return [dict(entry) for entry in entries]
        allowed = set(include_fields)
        return [
            {key: value for key, value in dict(entry).items() if key in allowed}
            for entry in entries
        ]

    def export_encrypted_json(self, password: str, options: Optional[ExportOptions] = None) -> str:
        selected_options = options or ExportOptions()
        entries = self.filter_entry_fields(
            self.get_entries_for_export(selected_options),
            selected_options.include_fields,
        )
        payload = {
            "entries": [self._serialize_entry(entry) for entry in entries],
            "entry_count": len(entries),
        }
        payload_bytes = json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
        compressed = bool(selected_options.compression)
        if compressed:
            payload_bytes = gzip.compress(payload_bytes)

        salt, _ = new_salt_and_nonce()
        key = derive_password_key(password, salt, bits=selected_options.encryption_strength)
        key_buffer = bytearray(key)
        try:
            nonce, ciphertext = encrypt_aes_gcm(payload_bytes, key_buffer)
            package_hmac = hmac.new(bytes(key_buffer), ciphertext, "sha256").hexdigest()
        finally:
            wipe_bytes(key_buffer)
        package = {
            "cryptosafe_export": True,
            "format": NativeJSONFormat.name,
            "version": NativeJSONFormat.version,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "metadata": {
                "mode": "selected" if selected_options.entry_ids else "full",
                "entry_count": len(entries),
                "fields": selected_options.include_fields or "all",
                "compressed": compressed,
            },
            "encryption": {
                "algorithm": "AES-256-GCM" if selected_options.encryption_strength == 256 else "AES-128-GCM",
                "kdf": "PBKDF2-HMAC-SHA256",
                "iterations": 100000,
                "salt": base64.b64encode(salt).decode("ascii"),
                "nonce": base64.b64encode(nonce).decode("ascii"),
            },
            "data": {
                "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
            },
            "integrity": {
                "checksum": checksum(ciphertext),
                "payload_checksum": checksum(payload_bytes),
                "hmac": package_hmac,
                "signature": package_hmac,
            },
        }
        output = NativeJSONFormat().serialize_header(package)
        self._record_history(
            operation_type="export",
            format="encrypted_json",
            encryption_used=package["encryption"]["algorithm"],
            entry_count=len(entries),
            file_size=len(output.encode("utf-8")),
            package_checksum=package["integrity"]["checksum"],
            verification_status="created",
            details=package["metadata"],
        )
        self._publish(EventType.EXPORT_OPERATION_COMPLETED, {"format": "encrypted_json", "entry_count": len(entries)})
        return output

    def export_encrypted_json_for_public_key(self, public_key: str, options: Optional[ExportOptions] = None) -> str:
        selected_options = options or ExportOptions()
        entries = self.filter_entry_fields(
            self.get_entries_for_export(selected_options),
            selected_options.include_fields,
        )
        payload = {
            "entries": [self._serialize_entry(entry) for entry in entries],
            "entry_count": len(entries),
        }
        payload_bytes = json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
        compressed = bool(selected_options.compression)
        if compressed:
            payload_bytes = gzip.compress(payload_bytes)

        encrypted = encrypt_with_public_key(payload_bytes, public_key)
        package = {
            "cryptosafe_export": True,
            "format": NativeJSONFormat.name,
            "version": NativeJSONFormat.version,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "metadata": {
                "mode": "selected" if selected_options.entry_ids else "full",
                "entry_count": len(entries),
                "fields": selected_options.include_fields or "all",
                "compressed": compressed,
            },
            "encryption": {
                "algorithm": encrypted["algorithm"],
                "method": encrypted["method"],
                "key_size": encrypted["key_size"],
                "key_fingerprint": encrypted["key_fingerprint"],
                "nonce": encrypted["nonce"],
            },
            "data": {
                "ciphertext": encrypted["ciphertext"],
                "encrypted_key": encrypted["encrypted_key"],
            },
            "integrity": {
                "checksum": encrypted["checksum"],
                "payload_checksum": checksum(payload_bytes),
                "signature": encrypted["checksum"],
            },
        }
        output = NativeJSONFormat().serialize_header(package)
        self._record_history(
            operation_type="export",
            format="encrypted_json",
            encryption_used=package["encryption"]["algorithm"],
            entry_count=len(entries),
            file_size=len(output.encode("utf-8")),
            package_checksum=package["integrity"]["checksum"],
            verification_status="created",
            details=package["metadata"],
        )
        self._publish(EventType.EXPORT_OPERATION_COMPLETED, {"format": "encrypted_json", "entry_count": len(entries)})
        return output

    def export_csv(self, options: Optional[ExportOptions] = None) -> str:
        selected_options = options or ExportOptions(format="csv", plaintext_allowed=True)
        if not selected_options.plaintext_allowed:
            raise ValueError("Plaintext CSV export must be explicitly allowed")
        entries = self.filter_entry_fields(
            self.get_entries_for_export(selected_options),
            selected_options.include_fields,
        )
        output = CSVVaultFormat().serialize_rows(self._serialize_entry(entry) for entry in entries)
        self._record_history(
            operation_type="export",
            format="csv",
            encryption_used="none",
            entry_count=len(entries),
            file_size=len(output.encode("utf-8")),
            package_checksum=checksum(output.encode("utf-8")),
            verification_status="created",
            details={"plaintext": True, "mode": "selected" if selected_options.entry_ids else "full"},
        )
        self._publish(EventType.EXPORT_OPERATION_COMPLETED, {"format": "csv", "entry_count": len(entries)})
        return output

    def export_bitwarden_json(self, options: Optional[ExportOptions] = None) -> str:
        selected_options = options or ExportOptions(format="bitwarden_json", plaintext_allowed=True)
        if not selected_options.plaintext_allowed:
            raise ValueError("Password-manager exports must be explicitly allowed because they are plaintext migration files")
        entries = self.filter_entry_fields(
            self.get_entries_for_export(selected_options),
            selected_options.include_fields,
        )
        output = BitwardenJSONFormat().serialize_entries([self._serialize_entry(entry) for entry in entries])
        self._record_history(
            operation_type="export",
            format="bitwarden_json",
            encryption_used="none",
            entry_count=len(entries),
            file_size=len(output.encode("utf-8")),
            package_checksum=checksum(output.encode("utf-8")),
            verification_status="created",
            details={"plaintext": True, "target": "bitwarden"},
        )
        self._publish(EventType.EXPORT_OPERATION_COMPLETED, {"format": "bitwarden_json", "entry_count": len(entries)})
        return output

    def export_bitwarden_encrypted_json(self, password: str, options: Optional[ExportOptions] = None) -> str:
        selected_options = options or ExportOptions(format="bitwarden_encrypted_json")
        entries = self.filter_entry_fields(
            self.get_entries_for_export(selected_options),
            selected_options.include_fields,
        )
        output = BitwardenEncryptedJSONFormat().serialize_entries(
            [self._serialize_entry(entry) for entry in entries],
            password,
        )
        self._record_history(
            operation_type="export",
            format="bitwarden_encrypted_json",
            encryption_used="Bitwarden password-protected JSON",
            entry_count=len(entries),
            file_size=len(output.encode("utf-8")),
            package_checksum=checksum(output.encode("utf-8")),
            verification_status="created",
            details={"plaintext": False, "target": "bitwarden"},
        )
        self._publish(EventType.EXPORT_OPERATION_COMPLETED, {"format": "bitwarden_encrypted_json", "entry_count": len(entries)})
        return output

    def export_lastpass_csv(self, options: Optional[ExportOptions] = None) -> str:
        selected_options = options or ExportOptions(format="lastpass_csv", plaintext_allowed=True)
        if not selected_options.plaintext_allowed:
            raise ValueError("Password-manager exports must be explicitly allowed because they are plaintext migration files")
        entries = self.filter_entry_fields(
            self.get_entries_for_export(selected_options),
            selected_options.include_fields,
        )
        output = LastPassCSVFormat().serialize_entries([self._serialize_entry(entry) for entry in entries])
        self._record_history(
            operation_type="export",
            format="lastpass_csv",
            encryption_used="none",
            entry_count=len(entries),
            file_size=len(output.encode("utf-8")),
            package_checksum=checksum(output.encode("utf-8")),
            verification_status="created",
            details={"plaintext": True, "target": "lastpass"},
        )
        self._publish(EventType.EXPORT_OPERATION_COMPLETED, {"format": "lastpass_csv", "entry_count": len(entries)})
        return output

    def _serialize_entry(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        safe_entry = dict(entry)
        for key, value in list(safe_entry.items()):
            if isinstance(value, datetime):
                safe_entry[key] = value.isoformat()
        return safe_entry

    def _record_history(
        self,
        *,
        operation_type: str,
        format: str,
        encryption_used: str,
        entry_count: int,
        file_size: int,
        package_checksum: str,
        verification_status: str,
        details: Dict[str, Any],
    ):
        if self.database is None:
            return
        self.database.add_import_export_history(
            operation_type=operation_type,
            format=format,
            encryption_used=encryption_used,
            entry_count=entry_count,
            file_size=file_size,
            checksum=package_checksum,
            verification_status=verification_status,
            details=details,
        )

    def _publish(self, event_type: EventType, data: Dict[str, Any]):
        if self.event_bus is not None:
            self.event_bus.publish(Event(event_type, data))