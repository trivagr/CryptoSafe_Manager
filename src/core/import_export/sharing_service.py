import base64
import hashlib
import hmac
import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict

from ..events import Event, EventType
from ..security.side_channel_protection import constant_time_compare
from .crypto import (
    checksum,
    decrypt_aes_gcm,
    decrypt_with_ec_private_key,
    decrypt_with_private_key,
    derive_password_key,
    encrypt_aes_gcm,
    encrypt_with_ec_public_key,
    encrypt_with_public_key,
    new_salt_and_nonce,
    public_key_fingerprint,
    wipe_bytes,
)
from .exceptions import ImportValidationError
from .models import SharePermissions


class SharingService:
    PACKAGE_VERSION = "1.0"
    ALLOWED_ENTRY_FIELDS = ("title", "username", "password", "url", "notes", "category", "tags")

    def __init__(self, entry_manager, database=None, event_bus=None):
        self.entry_manager = entry_manager
        self.database = database
        self.event_bus = event_bus

    def build_share_metadata(
        self,
        *,
        entry_id: int,
        recipient: str,
        encryption_method: str,
        permissions: SharePermissions,
    ) -> Dict[str, Any]:
        share_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(days=permissions.as_dict()["expires_in_days"])
        metadata = {
            "share_id": share_id,
            "original_entry_id": int(entry_id),
            "recipient_info": str(recipient),
            "encryption_method": str(encryption_method),
            "permissions": permissions.as_dict(),
            "shared_at": now,
            "expires_at": expires_at,
        }
        metadata["package_checksum"] = self._metadata_checksum(metadata)
        return metadata

    def create_password_share_package(
        self,
        *,
        entry_id: int,
        recipient: str,
        password: str,
        permissions: SharePermissions | None = None,
    ) -> str:
        selected_permissions = permissions or SharePermissions()
        metadata = self.build_share_metadata(
            entry_id=entry_id,
            recipient=recipient,
            encryption_method="password",
            permissions=selected_permissions,
        )
        entry = self.entry_manager.get_entry(entry_id)
        payload = {
            "entry": self._limited_entry_payload(entry),
            "permissions": metadata["permissions"],
            "share_id": metadata["share_id"],
        }
        plaintext = json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
        salt, _ = new_salt_and_nonce()
        key = derive_password_key(password, salt, bits=256)
        key_buffer = bytearray(key)
        associated_data = metadata["share_id"].encode("utf-8")
        try:
            nonce, ciphertext = encrypt_aes_gcm(plaintext, key_buffer, associated_data=associated_data)
            package_hmac = hmac.new(bytes(key_buffer), ciphertext, "sha256").hexdigest()
        finally:
            wipe_bytes(key_buffer)
        package = {
            "cryptosafe_share": True,
            "version": self.PACKAGE_VERSION,
            "metadata": self._serialize_metadata(metadata),
            "encryption": {
                "method": "password",
                "algorithm": "AES-256-GCM",
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
                "payload_checksum": checksum(plaintext),
                "hmac": package_hmac,
                "signature": package_hmac,
            },
        }
        package["metadata"]["package_checksum"] = package["integrity"]["checksum"]
        metadata["package_checksum"] = package["integrity"]["checksum"]
        self.remember_share(metadata)
        self._publish(EventType.SHARE_CREATED, {"share_id": metadata["share_id"], "entry_id": entry_id})
        return json.dumps(package, ensure_ascii=False, sort_keys=True)

    def preview_password_share_package(self, package_payload: str | bytes, password: str) -> Dict[str, Any]:
        package = self._load_share_package(package_payload)
        self._ensure_not_expired(package)
        plaintext = self._decrypt_share_payload(package, password)
        return self._validate_share_payload(plaintext)

    def import_password_share_package(self, package_payload: str | bytes, password: str) -> Dict[str, Any]:
        payload = self.preview_password_share_package(package_payload, password)
        entry = self.entry_manager.create_entry(payload["entry"])
        result = {
            "share_id": payload["share_id"],
            "created": 1,
            "entry_id": entry.get("id") if isinstance(entry, dict) else None,
            "permissions": payload["permissions"],
        }
        self._publish(EventType.SHARE_IMPORTED, result)
        return result

    def create_public_key_share_package(
        self,
        *,
        entry_id: int,
        recipient: str,
        public_key: str,
        sender_public_key: str = "",
        encryption_method: str = "public_key",
        permissions: SharePermissions | None = None,
    ) -> str:
        selected_permissions = permissions or SharePermissions()
        normalized_method = "ecies" if str(encryption_method).strip().lower() in {"ecies", "ecc", "p-256"} else "public_key"
        metadata = self.build_share_metadata(
            entry_id=entry_id,
            recipient=recipient,
            encryption_method=normalized_method,
            permissions=selected_permissions,
        )
        entry = self.entry_manager.get_entry(entry_id)
        payload = {
            "entry": self._limited_entry_payload(entry),
            "permissions": metadata["permissions"],
            "share_id": metadata["share_id"],
        }
        plaintext = json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
        if normalized_method == "ecies":
            encrypted = encrypt_with_ec_public_key(plaintext, public_key, associated_data=metadata["share_id"].encode("utf-8"))
        else:
            encrypted = encrypt_with_public_key(plaintext, public_key, associated_data=metadata["share_id"].encode("utf-8"))
        encryption = {
            "method": encrypted["method"],
            "algorithm": encrypted["algorithm"],
            "key_fingerprint": encrypted["key_fingerprint"],
            "nonce": encrypted["nonce"],
            "sender_public_key": str(sender_public_key or ""),
            "sender_fingerprint": public_key_fingerprint(sender_public_key) if sender_public_key else "",
        }
        if encrypted.get("key_size"):
            encryption["key_size"] = encrypted["key_size"]
        if encrypted.get("curve"):
            encryption["curve"] = encrypted["curve"]
        package = {
            "cryptosafe_share": True,
            "version": self.PACKAGE_VERSION,
            "metadata": self._serialize_metadata(metadata),
            "encryption": encryption,
            "data": {
                "ciphertext": encrypted["ciphertext"],
            },
            "integrity": {
                "checksum": encrypted["checksum"],
                "payload_checksum": checksum(plaintext),
                "signature": encrypted["checksum"],
            },
        }
        if encrypted.get("encrypted_key"):
            package["data"]["encrypted_key"] = encrypted["encrypted_key"]
        if encrypted.get("ephemeral_public_key"):
            package["data"]["ephemeral_public_key"] = encrypted["ephemeral_public_key"]
        package["metadata"]["package_checksum"] = package["integrity"]["checksum"]
        metadata["package_checksum"] = package["integrity"]["checksum"]
        self.remember_share(metadata)
        self._publish(EventType.SHARE_CREATED, {"share_id": metadata["share_id"], "entry_id": entry_id})
        return json.dumps(package, ensure_ascii=False, sort_keys=True)

    def preview_public_key_share_package(self, package_payload: str | bytes, private_key: str) -> Dict[str, Any]:
        package = self._load_share_package(package_payload)
        self._ensure_not_expired(package)
        plaintext = self._decrypt_public_key_share_payload(package, private_key)
        return self._validate_share_payload(plaintext)

    def import_public_key_share_package(self, package_payload: str | bytes, private_key: str) -> Dict[str, Any]:
        payload = self.preview_public_key_share_package(package_payload, private_key)
        entry = self.entry_manager.create_entry(payload["entry"])
        result = {
            "share_id": payload["share_id"],
            "created": 1,
            "entry_id": entry.get("id") if isinstance(entry, dict) else None,
            "permissions": payload["permissions"],
        }
        self._publish(EventType.SHARE_IMPORTED, result)
        return result

    def remember_share(self, metadata: Dict[str, Any]):
        if self.database is None:
            return
        self.database.add_shared_entry(
            share_id=metadata["share_id"],
            original_entry_id=metadata["original_entry_id"],
            encryption_method=metadata["encryption_method"],
            recipient_info=metadata["recipient_info"],
            permissions=metadata["permissions"],
            shared_at=metadata["shared_at"],
            expires_at=metadata["expires_at"],
            package_checksum=metadata.get("package_checksum", ""),
        )

    def _metadata_checksum(self, metadata: Dict[str, Any]) -> str:
        checksum_payload = "|".join(
            [
                str(metadata.get("share_id", "")),
                str(metadata.get("original_entry_id", "")),
                str(metadata.get("recipient_info", "")),
                str(metadata.get("encryption_method", "")),
            ]
        )
        return hashlib.sha256(checksum_payload.encode("utf-8")).hexdigest()

    def _limited_entry_payload(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        return {
            field: str(entry.get(field, "") or "")
            for field in self.ALLOWED_ENTRY_FIELDS
        }

    def _serialize_metadata(self, metadata: Dict[str, Any]) -> Dict[str, Any]:
        serialized = dict(metadata)
        for key in ("shared_at", "expires_at"):
            if isinstance(serialized.get(key), datetime):
                serialized[key] = serialized[key].isoformat()
        return serialized

    def _load_share_package(self, package_payload: str | bytes) -> Dict[str, Any]:
        try:
            raw = package_payload.decode("utf-8") if isinstance(package_payload, bytes) else str(package_payload)
            package = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ImportValidationError("Share package is invalid JSON") from exc
        if not isinstance(package, dict) or not package.get("cryptosafe_share"):
            raise ImportValidationError("File is not a CryptoSafe share package")
        for field in ("metadata", "encryption", "data", "integrity"):
            if not isinstance(package.get(field), dict):
                raise ImportValidationError(f"Share package is missing {field}")
        ciphertext = self._decode_b64(package["data"].get("ciphertext", ""))
        if checksum(ciphertext) != str(package["integrity"].get("checksum", "")):
            raise ImportValidationError("Share package checksum does not match")
        return package

    def _ensure_not_expired(self, package: Dict[str, Any]):
        expires_at = str(package["metadata"].get("expires_at", ""))
        try:
            parsed = datetime.fromisoformat(expires_at)
        except ValueError as exc:
            raise ImportValidationError("Share package expiration is invalid") from exc
        if parsed < datetime.now(timezone.utc):
            raise ImportValidationError("Share package has expired")

    def _decrypt_share_payload(self, package: Dict[str, Any], password: str) -> Dict[str, Any]:
        encryption = package["encryption"]
        salt = self._decode_b64(encryption.get("salt", ""))
        nonce = self._decode_b64(encryption.get("nonce", ""))
        ciphertext = self._decode_b64(package["data"].get("ciphertext", ""))
        key = derive_password_key(password, salt, bits=256, iterations=int(encryption.get("iterations", 100000)))
        key_buffer = bytearray(key)
        associated_data = str(package["metadata"].get("share_id", "")).encode("utf-8")
        try:
            expected_hmac = str(package["integrity"].get("hmac", ""))
            if expected_hmac and not constant_time_compare(hmac.new(bytes(key_buffer), ciphertext, "sha256").hexdigest(), expected_hmac):
                raise ImportValidationError("Share package HMAC does not match")
            plaintext = decrypt_aes_gcm(ciphertext, key_buffer, nonce, associated_data=associated_data)
        finally:
            wipe_bytes(key_buffer)
        if checksum(plaintext) != str(package["integrity"].get("payload_checksum", "")):
            raise ImportValidationError("Share package plaintext checksum does not match")
        try:
            decoded = json.loads(plaintext.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ImportValidationError("Share package payload is invalid") from exc
        if not isinstance(decoded, dict):
            raise ImportValidationError("Share package payload must be an object")
        return decoded

    def _decrypt_public_key_share_payload(self, package: Dict[str, Any], private_key: str) -> Dict[str, Any]:
        encrypted_payload = {
            "encrypted_key": package["data"].get("encrypted_key", ""),
            "ephemeral_public_key": package["data"].get("ephemeral_public_key", ""),
            "nonce": package["encryption"].get("nonce", ""),
            "ciphertext": package["data"].get("ciphertext", ""),
            "checksum": package["integrity"].get("checksum", ""),
        }
        associated_data = str(package["metadata"].get("share_id", "")).encode("utf-8")
        if str(package["encryption"].get("method", "")).lower() == "ecies":
            plaintext = decrypt_with_ec_private_key(encrypted_payload, private_key, associated_data=associated_data)
        else:
            plaintext = decrypt_with_private_key(encrypted_payload, private_key, associated_data=associated_data)
        if checksum(plaintext) != str(package["integrity"].get("payload_checksum", "")):
            raise ImportValidationError("Share package plaintext checksum does not match")
        try:
            decoded = json.loads(plaintext.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ImportValidationError("Share package payload is invalid") from exc
        if not isinstance(decoded, dict):
            raise ImportValidationError("Share package payload must be an object")
        return decoded

    def _validate_share_payload(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        entry = payload.get("entry")
        permissions = payload.get("permissions")
        if not isinstance(entry, dict) or not isinstance(permissions, dict):
            raise ImportValidationError("Share package payload is incomplete")
        if not entry.get("title") or not entry.get("password"):
            raise ImportValidationError("Share package entry is missing required fields")
        return {
            "share_id": str(payload.get("share_id", "")),
            "entry": self._limited_entry_payload(entry),
            "permissions": permissions,
        }

    def _decode_b64(self, value: str) -> bytes:
        try:
            return base64.b64decode(str(value).encode("ascii"), validate=True)
        except Exception as exc:
            raise ImportValidationError("Share package contains invalid base64 data") from exc

    def _publish(self, event_type: EventType, data: Dict[str, Any]):
        if self.event_bus is not None:
            self.event_bus.publish(Event(event_type, data))