import base64
import json
import os
import uuid
from typing import Any, Dict, List

from cryptography.hazmat.primitives import hashes, hmac, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from ..exceptions import ImportValidationError


BITWARDEN_PASSWORD_PROTECTED_ITERATIONS = 600_000


def _b64(data: bytes) -> str:
    return base64.b64encode(bytes(data)).decode("ascii")


def _derive_bitwarden_pin_key(password: str, salt_text: str, iterations: int) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=str(salt_text).encode("utf-8"),
        iterations=max(BITWARDEN_PASSWORD_PROTECTED_ITERATIONS, int(iterations)),
    )
    return kdf.derive(str(password).encode("utf-8"))


def _stretch_bitwarden_key(pin_key: bytes) -> tuple[bytes, bytes]:
    enc_key = HKDFExpand(algorithm=hashes.SHA256(), length=32, info=b"enc").derive(bytes(pin_key))
    mac_key = HKDFExpand(algorithm=hashes.SHA256(), length=32, info=b"mac").derive(bytes(pin_key))
    return enc_key, mac_key


def _encrypt_bitwarden_enc_string(value: str, enc_key: bytes, mac_key: bytes) -> str:
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(str(value).encode("utf-8")) + padder.finalize()
    encryptor = Cipher(algorithms.AES(bytes(enc_key)), modes.CBC(iv)).encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    signer = hmac.HMAC(bytes(mac_key), hashes.SHA256())
    signer.update(iv)
    signer.update(ciphertext)
    mac = signer.finalize()
    return f"2.{_b64(iv)}|{_b64(ciphertext)}|{_b64(mac)}"


def decrypt_bitwarden_password_protected_export(payload: str | bytes, password: str) -> Dict[str, Any]:
    try:
        package = json.loads(payload.decode("utf-8") if isinstance(payload, bytes) else payload)
        enc_string = str(package["data"])
        enc_type, encoded_parts = enc_string.split(".", 1)
        iv_text, ciphertext_text, mac_text = encoded_parts.split("|", 2)
    except Exception as exc:
        raise ImportValidationError("Зашифрованный JSON Bitwarden повреждён или имеет неверный формат") from exc
    if enc_type != "2":
        raise ImportValidationError("Зашифрованный JSON Bitwarden использует неподдерживаемый тип шифрования")

    pin_key = _derive_bitwarden_pin_key(
        password,
        str(package.get("salt", "")),
        int(package.get("kdfIterations", BITWARDEN_PASSWORD_PROTECTED_ITERATIONS)),
    )
    enc_key, mac_key = _stretch_bitwarden_key(pin_key)
    iv = base64.b64decode(iv_text)
    ciphertext = base64.b64decode(ciphertext_text)
    expected_mac = base64.b64decode(mac_text)
    signer = hmac.HMAC(mac_key, hashes.SHA256())
    signer.update(iv)
    signer.update(ciphertext)
    try:
        signer.verify(expected_mac)
    except Exception as exc:
        raise ImportValidationError("Не удалось проверить пароль или подлинность зашифрованного JSON Bitwarden") from exc

    decryptor = Cipher(algorithms.AES(enc_key), modes.CBC(iv)).decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded) + unpadder.finalize()
    try:
        return json.loads(plaintext.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise ImportValidationError("Расшифрованные данные JSON Bitwarden имеют неверный формат") from exc


class BitwardenJSONFormat:
    name = "bitwarden_json"

    def serialize_entries(self, entries: List[Dict[str, Any]]) -> str:
        return json.dumps(self.build_plain_export(entries), ensure_ascii=False, sort_keys=True)

    def build_plain_export(self, entries: List[Dict[str, Any]]) -> Dict[str, Any]:
        folder_ids: Dict[str, str] = {}
        for entry in entries:
            category = str(entry.get("category", "") or "").strip()
            if category and category not in folder_ids:
                folder_ids[category] = str(uuid.uuid5(uuid.NAMESPACE_URL, f"cryptosafe-folder:{category}"))

        folders = [
            {
                "id": folder_id,
                "name": folder_name,
            }
            for folder_name, folder_id in sorted(folder_ids.items())
        ]
        items = []
        for entry in entries:
            title = str(entry.get("title", "") or "Untitled")
            category = str(entry.get("category", "") or "").strip()
            url = str(entry.get("url", "") or "").strip()
            tags = [
                {"name": tag.strip(), "type": 0, "value": "true"}
                for tag in str(entry.get("tags", "") or "").split(",")
                if tag.strip()
            ]
            items.append(
                {
                    "id": str(uuid.uuid5(uuid.NAMESPACE_URL, f"cryptosafe-item:{entry.get('id', title)}:{title}")),
                    "organizationId": None,
                    "folderId": folder_ids.get(category),
                    "type": 1,
                    "reprompt": 0,
                    "name": title,
                    "notes": str(entry.get("notes", "") or ""),
                    "favorite": False,
                    "login": {
                        "uris": [{"match": None, "uri": url}] if url else [],
                        "username": str(entry.get("username", "") or ""),
                        "password": str(entry.get("password", "") or ""),
                        "totp": None,
                    },
                    "fields": tags,
                }
            )
        return {"encrypted": False, "folders": folders, "items": items}

    def parse_entries(self, payload: str) -> List[Dict[str, str]]:
        try:
            parsed = json.loads(payload)
        except json.JSONDecodeError as exc:
            raise ImportValidationError("Bitwarden JSON is invalid") from exc
        folders = parsed.get("folders", []) if isinstance(parsed, dict) else []
        folder_names = {
            str(folder.get("id")): str(folder.get("name") or "")
            for folder in folders
            if isinstance(folder, dict) and folder.get("id")
        }
        items = parsed.get("items") if isinstance(parsed, dict) else None
        if not isinstance(items, list):
            if isinstance(parsed, dict) and parsed.get("encrypted") and parsed.get("data"):
                raise ImportValidationError("Это зашифрованный JSON Bitwarden. Выберите формат «Зашифрованный Bitwarden JSON» и введите пароль экспорта.")
            raise ImportValidationError("JSON Bitwarden не содержит список items")
        entries = []
        for item in items:
            if not isinstance(item, dict) or item.get("type") not in {None, 1}:
                continue
            login = item.get("login") or {}
            if not isinstance(login, dict):
                login = {}
            uris = login.get("uris") or []
            url = ""
            if uris and isinstance(uris[0], dict):
                url = str(uris[0].get("uri") or "")
            fields = item.get("fields") or []
            tags = ",".join(str(field.get("name", "")).strip() for field in fields if isinstance(field, dict) and field.get("name"))
            entries.append(
                {
                    "title": str(item.get("name") or ""),
                    "username": str(login.get("username") or ""),
                    "password": str(login.get("password") or ""),
                    "url": url,
                    "notes": str(item.get("notes") or ""),
                    "category": folder_names.get(str(item.get("folderId")), str(item.get("folderId") or "")),
                    "tags": tags,
                }
            )
        return entries


class LastPassCSVFormat:
    name = "lastpass_csv"

    def serialize_entries(self, entries: List[Dict[str, Any]]) -> str:
        import csv
        import io

        output = io.StringIO(newline="")
        fieldnames = ["url", "username", "password", "extra", "name", "grouping"]
        writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for entry in entries:
            writer.writerow(
                {
                    "url": str(entry.get("url", "") or ""),
                    "username": str(entry.get("username", "") or ""),
                    "password": str(entry.get("password", "") or ""),
                    "extra": str(entry.get("notes", "") or ""),
                    "name": str(entry.get("title", "") or ""),
                    "grouping": str(entry.get("category", "") or ""),
                }
            )
        return output.getvalue()

    def parse_entries(self, payload: str) -> List[Dict[str, str]]:
        from .csv_format import CSVVaultFormat

        return CSVVaultFormat().parse_rows(payload)


class BitwardenEncryptedJSONFormat:
    name = "bitwarden_encrypted_json"

    def serialize_entries(self, entries: List[Dict[str, Any]], password: str) -> str:
        if not password:
            raise ValueError("Для экспорта зашифрованного JSON Bitwarden нужен пароль")
        plain_export = BitwardenJSONFormat().build_plain_export(entries)
        plain_payload = json.dumps(plain_export, ensure_ascii=False, sort_keys=True)
        salt = _b64(os.urandom(16))
        pin_key = _derive_bitwarden_pin_key(password, salt, BITWARDEN_PASSWORD_PROTECTED_ITERATIONS)
        enc_key, mac_key = _stretch_bitwarden_key(pin_key)
        package = {
            "encrypted": True,
            "passwordProtected": True,
            "salt": salt,
            "kdfType": 0,
            "kdfIterations": BITWARDEN_PASSWORD_PROTECTED_ITERATIONS,
            "kdfMemory": None,
            "kdfParallelism": None,
            "encKeyValidation_DO_NOT_EDIT": _encrypt_bitwarden_enc_string(str(uuid.uuid4()), enc_key, mac_key),
            "data": _encrypt_bitwarden_enc_string(plain_payload, enc_key, mac_key),
        }
        return json.dumps(package, ensure_ascii=False, indent=2, sort_keys=True)