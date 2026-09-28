import re
import base64
import gzip
import hmac
import json
import time
from typing import Any, Dict, Iterable, List

from ..events import Event, EventType
from ..security.side_channel_protection import constant_time_compare
from .crypto import checksum, decrypt_aes_gcm, decrypt_with_private_key, derive_password_key, wipe_bytes
from .exceptions import ImportValidationError
from .formats import BitwardenJSONFormat, CSVVaultFormat, LastPassCSVFormat, NativeJSONFormat
from .formats.password_manager import decrypt_bitwarden_password_protected_export
from .models import ImportOptions


class VaultImporter:
    MALICIOUS_PATTERNS = (
        re.compile(r"<\s*script", re.IGNORECASE),
        re.compile(r"javascript\s*:", re.IGNORECASE),
        re.compile(r"<\s*iframe", re.IGNORECASE),
    )

    def __init__(self, entry_manager, database=None, event_bus=None):
        self.entry_manager = entry_manager
        self.database = database
        self.event_bus = event_bus

    def validate_entries(self, entries: Iterable[Dict[str, Any]], options: ImportOptions | None = None) -> List[Dict[str, Any]]:
        _ = options or ImportOptions()
        validated = []
        for index, entry in enumerate(entries, start=1):
            normalized = self._sanitize_entry(entry)
            if not normalized["title"]:
                raise ImportValidationError(f"Entry #{index} is missing title")
            if not normalized["password"]:
                raise ImportValidationError(f"Entry #{index} is missing password")
            validated.append(normalized)
        return validated

    def preview_encrypted_json(self, package_payload: str | bytes, password: str, options: ImportOptions | None = None) -> List[Dict[str, Any]]:
        import_options = options or ImportOptions(format="encrypted_json")
        package = self._load_native_package(package_payload, import_options)
        plaintext = self._decrypt_native_payload(package, password)
        entries = self.validate_entries(plaintext.get("entries", []), import_options)
        return entries

    def import_encrypted_json(self, package_payload: str | bytes, password: str, options: ImportOptions | None = None) -> Dict[str, Any]:
        started = time.monotonic()
        import_options = options or ImportOptions(format="encrypted_json", mode="dry-run")
        entries = self.preview_encrypted_json(package_payload, password, import_options)
        result = {"validated": len(entries), "created": 0, "updated": 0, "skipped": 0, "mode": import_options.mode}
        if import_options.mode == "dry-run":
            self._record_history("import", "encrypted_json", "AES-GCM", len(entries), len(self._as_bytes(package_payload)), "dry-run", "validated", result)
            self._publish(EventType.IMPORT_OPERATION_COMPLETED, result)
            return result

        if import_options.mode == "replace":
            self._clear_vault()
        existing = {} if import_options.mode == "replace" else self._existing_entries_by_identity()
        deadline = started + max(1, int(import_options.timeout_seconds))
        for entry in entries:
            if time.monotonic() > deadline:
                raise ImportValidationError("Import timed out")
            identity = self._identity(entry)
            existing_entry = existing.get(identity)
            if existing_entry and import_options.duplicate_strategy == "skip":
                result["skipped"] += 1
                continue
            if existing_entry and import_options.duplicate_strategy == "replace":
                self.entry_manager.update_entry(existing_entry["id"], entry)
                result["updated"] += 1
                continue
            self.entry_manager.create_entry(entry)
            result["created"] += 1

        self._record_history("import", "encrypted_json", "AES-GCM", len(entries), len(self._as_bytes(package_payload)), "applied", "verified", result)
        self._publish(EventType.IMPORT_OPERATION_COMPLETED, result)
        return result

    def preview_plaintext(self, payload: str | bytes, options: ImportOptions | None = None) -> List[Dict[str, Any]]:
        import_options = options or ImportOptions(format="csv")
        raw_entries = self._parse_plaintext_payload(payload, import_options)
        return self.validate_entries(raw_entries, import_options)

    def preview_bitwarden_encrypted_json(self, payload: str | bytes, password: str, options: ImportOptions | None = None) -> List[Dict[str, Any]]:
        if not password:
            raise ImportValidationError("Для зашифрованного JSON Bitwarden нужен пароль экспорта")
        import_options = options or ImportOptions(format="bitwarden_encrypted_json")
        decrypted = decrypt_bitwarden_password_protected_export(payload, password)
        raw_entries = BitwardenJSONFormat().parse_entries(json.dumps(decrypted))
        return self.validate_entries(raw_entries, import_options)

    def import_bitwarden_encrypted_json(self, payload: str | bytes, password: str, options: ImportOptions | None = None) -> Dict[str, Any]:
        started = time.monotonic()
        import_options = options or ImportOptions(format="bitwarden_encrypted_json", mode="dry-run")
        entries = self.preview_bitwarden_encrypted_json(payload, password, import_options)
        result = self._apply_entries(entries, import_options, started)
        self._record_history(
            "import",
            "bitwarden_encrypted_json",
            "Bitwarden password-protected JSON",
            len(entries),
            len(self._as_bytes(payload)),
            "dry-run" if import_options.mode == "dry-run" else checksum(self._as_bytes(payload)),
            "validated" if import_options.mode == "dry-run" else "verified",
            result,
        )
        self._publish(EventType.IMPORT_OPERATION_COMPLETED, result)
        return result

    def import_plaintext(self, payload: str | bytes, options: ImportOptions | None = None) -> Dict[str, Any]:
        started = time.monotonic()
        import_options = options or ImportOptions(format="csv", mode="dry-run")
        entries = self.preview_plaintext(payload, import_options)
        result = self._apply_entries(entries, import_options, started)
        self._record_history(
            "import",
            import_options.format,
            "none",
            len(entries),
            len(self._as_bytes(payload)),
            checksum(self._as_bytes(payload)),
            "validated" if import_options.mode == "dry-run" else "verified",
            result,
        )
        self._publish(EventType.IMPORT_OPERATION_COMPLETED, result)
        return result

    def _sanitize_entry(self, entry: Dict[str, Any]) -> Dict[str, str]:
        normalized = {
            "title": self._sanitize_text(entry.get("title", "")),
            "username": self._sanitize_text(entry.get("username", "")),
            "password": str(entry.get("password", "") or ""),
            "url": self._sanitize_text(entry.get("url", "")),
            "notes": self._sanitize_text(entry.get("notes", "")),
            "category": self._sanitize_text(entry.get("category", "")),
            "tags": self._sanitize_text(entry.get("tags", "")),
        }
        return normalized

    def _sanitize_text(self, value: Any) -> str:
        text = str(value or "").replace("\x00", "").strip()
        for pattern in self.MALICIOUS_PATTERNS:
            if pattern.search(text):
                raise ImportValidationError("Imported data contains blocked active content")
        return text

    def _load_native_package(self, package_payload: str | bytes, options: ImportOptions) -> Dict[str, Any]:
        payload_bytes = self._as_bytes(package_payload)
        if len(payload_bytes) > max(1, int(options.max_file_size)):
            raise ImportValidationError("Import file exceeds the maximum allowed size")
        try:
            package = NativeJSONFormat().deserialize_header(payload_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise ImportValidationError("Native export package is invalid JSON") from exc
        NativeJSONFormat().validate_package(package)
        ciphertext = self._decode_b64(package["data"].get("ciphertext", ""))
        expected_checksum = str(package["integrity"].get("checksum", ""))
        if checksum(ciphertext) != expected_checksum:
            raise ImportValidationError("Native export checksum does not match")
        return package

    def _parse_plaintext_payload(self, payload: str | bytes, options: ImportOptions) -> List[Dict[str, str]]:
        payload_bytes = self._as_bytes(payload)
        if len(payload_bytes) > max(1, int(options.max_file_size)):
            raise ImportValidationError("Import file exceeds the maximum allowed size")
        text = payload_bytes.decode("utf-8-sig")
        normalized_format = str(options.format or "csv").strip().lower()
        if normalized_format in {"csv", "cryptosafe_csv"}:
            return CSVVaultFormat().parse_rows(text)
        if normalized_format in {"lastpass", "lastpass_csv"}:
            return LastPassCSVFormat().parse_entries(text)
        if normalized_format in {"bitwarden", "bitwarden_json"}:
            return BitwardenJSONFormat().parse_entries(text)
        raise ImportValidationError(f"Unsupported import format: {options.format}")

    def _decrypt_native_payload(self, package: Dict[str, Any], password: str) -> Dict[str, Any]:
        encryption = package["encryption"]
        if str(encryption.get("method", "")).lower() == "public_key":
            plaintext = decrypt_with_private_key(
                {
                    "encrypted_key": package["data"].get("encrypted_key", ""),
                    "nonce": encryption.get("nonce", ""),
                    "ciphertext": package["data"].get("ciphertext", ""),
                    "checksum": package["integrity"].get("checksum", ""),
                },
                password,
            )
            return self._decode_native_plaintext(package, plaintext)

        salt = self._decode_b64(encryption.get("salt", ""))
        nonce = self._decode_b64(encryption.get("nonce", ""))
        ciphertext = self._decode_b64(package["data"].get("ciphertext", ""))
        bits = 128 if "128" in str(encryption.get("algorithm", "")) else 256
        key = derive_password_key(password, salt, bits=bits, iterations=int(encryption.get("iterations", 100000)))
        key_buffer = bytearray(key)
        try:
            expected_hmac = str(package["integrity"].get("hmac", ""))
            if expected_hmac and not constant_time_compare(hmac.new(bytes(key_buffer), ciphertext, "sha256").hexdigest(), expected_hmac):
                raise ImportValidationError("Native export HMAC does not match")
            plaintext = decrypt_aes_gcm(ciphertext, key_buffer, nonce)
        finally:
            wipe_bytes(key_buffer)
        return self._decode_native_plaintext(package, plaintext)

    def estimate_import_export_memory_ratio(self, payload: str | bytes, entries: List[Dict[str, Any]]) -> float:
        payload_size = max(1, len(self._as_bytes(payload)))
        entry_size = len(json.dumps(entries, ensure_ascii=False, sort_keys=True).encode("utf-8"))
        return entry_size / payload_size

    def _decode_native_plaintext(self, package: Dict[str, Any], plaintext: bytes) -> Dict[str, Any]:
        if checksum(plaintext) != str(package["integrity"].get("payload_checksum", "")):
            raise ImportValidationError("Native export plaintext checksum does not match")
        if package.get("metadata", {}).get("compressed"):
            plaintext = gzip.decompress(plaintext)
        try:
            decoded = json.loads(plaintext.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ImportValidationError("Native export decrypted payload is invalid") from exc
        if not isinstance(decoded, dict) or not isinstance(decoded.get("entries"), list):
            raise ImportValidationError("Native export payload does not contain entries")
        return decoded

    def _decode_b64(self, value: str) -> bytes:
        try:
            return base64.b64decode(str(value).encode("ascii"), validate=True)
        except Exception as exc:
            raise ImportValidationError("Native export contains invalid base64 data") from exc

    def _as_bytes(self, value: str | bytes) -> bytes:
        if isinstance(value, bytes):
            return value
        return str(value).encode("utf-8")

    def _existing_entries_by_identity(self) -> Dict[tuple[str, str], Dict[str, Any]]:
        if not hasattr(self.entry_manager, "get_all_entries"):
            return {}
        return {self._identity(entry): entry for entry in self.entry_manager.get_all_entries()}

    def _identity(self, entry: Dict[str, Any]) -> tuple[str, str]:
        return (str(entry.get("title", "")).strip().lower(), str(entry.get("username", "")).strip().lower())

    def _apply_entries(self, entries: List[Dict[str, Any]], options: ImportOptions, started: float) -> Dict[str, Any]:
        result = {"validated": len(entries), "created": 0, "updated": 0, "skipped": 0, "mode": options.mode}
        if options.mode == "dry-run":
            return result

        if options.mode == "replace":
            self._clear_vault()
        existing = {} if options.mode == "replace" else self._existing_entries_by_identity()
        deadline = started + max(1, int(options.timeout_seconds))
        for entry in entries:
            if time.monotonic() > deadline:
                raise ImportValidationError("Import timed out")
            identity = self._identity(entry)
            existing_entry = existing.get(identity)
            if existing_entry and options.duplicate_strategy == "skip":
                result["skipped"] += 1
                continue
            if existing_entry and options.duplicate_strategy == "replace":
                self.entry_manager.update_entry(existing_entry["id"], entry)
                result["updated"] += 1
                continue
            created = self.entry_manager.create_entry(entry)
            existing[identity] = created
            result["created"] += 1
        return result

    def _clear_vault(self):
        if hasattr(self.entry_manager, "get_all_entries") and hasattr(self.entry_manager, "delete_entry"):
            for entry in list(self.entry_manager.get_all_entries()):
                self.entry_manager.delete_entry(int(entry["id"]), soft_delete=False)
            return
        if hasattr(self.entry_manager, "entries"):
            self.entry_manager.entries = []

    def _record_history(
        self,
        operation_type: str,
        format: str,
        encryption_used: str,
        entry_count: int,
        file_size: int,
        checksum_value: str,
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
            checksum=checksum_value,
            verification_status=verification_status,
            details=details,
        )

    def _publish(self, event_type: EventType, data: Dict[str, Any]):
        if self.event_bus is not None:
            self.event_bus.publish(Event(event_type, data))