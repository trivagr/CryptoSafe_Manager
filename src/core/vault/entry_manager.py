import json
import hashlib
import re
from difflib import SequenceMatcher
from datetime import date, datetime, time, timedelta
from typing import Any, Dict, List, Optional

from ..crypto.password_validator import PasswordValidator
from ..events import Event, EventType, event_bus
from .encryption_service import AESGCMEncryptionService, VaultEncryptionError
from .search_index import SearchIndex


class EntryNotFoundError(Exception):
    pass


class EntryManager:
    PAYLOAD_VERSION = 1
    FUZZY_MATCH_THRESHOLD = 0.78

    def __init__(self, database, encryption_service: AESGCMEncryptionService, legacy_encryption_service=None):  #класс для управления записями в хранилище, который взаимодействует с базой данных и службой шифрования для создания, получения, обновления и удаления записей
        self.database = database
        self.encryption_service = encryption_service
        self.legacy_encryption_service = legacy_encryption_service
        self.password_validator = PasswordValidator()
        self.search_index = SearchIndex()
        self._search_index_ready = False

    def create_entry(self, data_dict: Dict[str, Any]) -> Dict[str, Any]:
        normalized = self._normalize_entry_data(data_dict)
        now = datetime.now()
        encrypted_payload = self._encrypt_payload(normalized, created_at=now)

        with self.database.transaction() as conn:
            cursor = conn.execute(
                """
                INSERT INTO vault_entries
                (title, username, encrypted_password, encrypted_data, url, notes, category, created_at, updated_at, tags)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    normalized["title"],
                    normalized["username"],
                    b"",
                    encrypted_payload,
                    normalized["url"],
                    normalized["notes"],
                    normalized["category"],
                    now.isoformat(),
                    now.isoformat(),
                    normalized["tags"],
                ),
            )
            entry_id = cursor.lastrowid

        entry = self.get_entry(entry_id)
        self._update_search_index_entry(entry)
        event_bus.publish(Event(EventType.ENTRY_ADDED, {"id": entry_id, "title": entry["title"]}))
        return entry

    def get_entry(self, entry_id: int) -> Dict[str, Any]:
        row = self.database.get_entry(entry_id)
        if row is None:
            raise EntryNotFoundError("Requested entry is unavailable")
        entry = self._deserialize_entry(row)
        event_bus.publish(Event(EventType.ENTRY_VIEWED, {"id": entry_id, "title": entry["title"]}))
        return entry

    def get_all_entries(self) -> List[Dict[str, Any]]:
        entries = self.database.get_all_entries()
        decrypted_entries = [self._deserialize_entry(entry) for entry in entries]
        if not self._search_index_ready:
            self._rebuild_search_index(decrypted_entries)
        return decrypted_entries

    def search_entries(
        self,
        query: str = "",
        category: str = "",
        entries: Optional[List[Dict[str, Any]]] = None,
        updated_from: Optional[Any] = None,
        updated_to: Optional[Any] = None,
        password_strength: str = "",
        tag: str = "",
    ) -> List[Dict[str, Any]]:
        source_entries = entries if entries is not None else self.get_all_entries()
        search_text = str(query or "").strip().lower()
        selected_category = str(category or "").strip()
        selected_tag = str(tag or "").strip().lower()
        updated_from_dt = self._normalize_filter_date(updated_from, is_end=False)
        updated_to_dt = self._normalize_filter_date(updated_to, is_end=True)
        selected_strength = str(password_strength or "").strip().lower()
        general_terms, field_filters = self._parse_search_query(search_text)
        indexed_candidate_ids = None if entries is not None else self._candidate_entry_ids_for_search(
            general_terms,
            field_filters,
            selected_tag,
        )

        filtered_entries = []
        for entry in source_entries:
            if indexed_candidate_ids is not None and entry.get("id") not in indexed_candidate_ids:
                continue
            if selected_category not in {"", "Все"} and str(entry.get("category", "")).strip() != selected_category:
                continue
            if not self._matches_tag_filter(entry, selected_tag):
                continue
            if not self._matches_updated_range(entry, updated_from_dt, updated_to_dt):
                continue
            if not self._matches_password_strength(entry, selected_strength):
                continue
            if not self._matches_field_filters(entry, field_filters):
                continue
            if self._matches_general_terms(entry, general_terms):
                filtered_entries.append(entry)

        self._publish_search_event(
            query=search_text,
            category=selected_category,
            tag=selected_tag,
            result_count=len(filtered_entries),
        )
        return filtered_entries

    def update_entry(self, entry_id: int, data_dict: Dict[str, Any]) -> Dict[str, Any]:
        current_entry = self.database.get_entry(entry_id)
        if current_entry is None:
            raise EntryNotFoundError("Requested entry is unavailable")

        current_data = self._deserialize_entry(current_entry)
        merged_data = {
            "title": current_data["title"],
            "username": current_data["username"],
            "password": current_data["password"],
            "url": current_data["url"],
            "notes": current_data["notes"],
            "category": current_data["category"],
            "tags": current_data["tags"],
            "clipboard_policy": current_data.get("clipboard_policy", "allow"),
            "totp_secret": current_data["totp_secret"],
            "sharing_metadata": current_data["sharing_metadata"],
        }
        merged_data.update(data_dict)

        normalized = self._normalize_entry_data(merged_data)
        updated_at = datetime.now()
        encrypted_payload = self._encrypt_payload(normalized, created_at=current_entry.created_at or updated_at)

        with self.database.transaction() as conn:
            conn.execute(
                """
                UPDATE vault_entries
                SET title = ?, username = ?, encrypted_password = ?, encrypted_data = ?, url = ?, notes = ?, category = ?, updated_at = ?, tags = ?
                WHERE id = ?
                """,
                (
                    normalized["title"],
                    normalized["username"],
                    current_entry.encrypted_password,
                    encrypted_payload,
                    normalized["url"],
                    normalized["notes"],
                    normalized["category"],
                    updated_at.isoformat(),
                    normalized["tags"],
                    entry_id,
                ),
            )

        entry = self.get_entry(entry_id)
        self._update_search_index_entry(entry)
        event_bus.publish(Event(EventType.ENTRY_UPDATED, {"id": entry_id, "title": entry["title"]}))
        return entry

    def delete_entry(self, entry_id: int, soft_delete: bool = True):
        existing_entry = self.database.get_entry(entry_id)
        if existing_entry is None:
            raise EntryNotFoundError("Requested entry is unavailable")

        title = existing_entry.title
        with self.database.transaction() as conn:
            if soft_delete:
                conn.execute(
                    """
                    INSERT INTO deleted_entries (original_entry_id, encrypted_data, title, deleted_at, expires_at)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        entry_id,
                        existing_entry.encrypted_data or existing_entry.encrypted_password,
                        title,
                        datetime.now().isoformat(),
                        self._default_soft_delete_expiration().isoformat(),
                    ),
                )
            conn.execute("DELETE FROM vault_entries WHERE id = ?", (entry_id,))

        event_bus.publish(Event(EventType.ENTRY_DELETED, {"id": entry_id, "title": title}))
        self._remove_search_index_entry(entry_id)

    def _normalize_entry_data(self, data_dict: Dict[str, Any]) -> Dict[str, Any]:
        normalized = {
            "title": str(data_dict.get("title", "")).strip(),
            "username": str(data_dict.get("username", "")).strip(),
            "password": str(data_dict.get("password", "")),
            "url": str(data_dict.get("url", "")).strip(),
            "notes": str(data_dict.get("notes", "")).strip(),
            "category": str(data_dict.get("category", "")).strip(),
            "tags": self._normalize_tags(data_dict.get("tags", "")),
            "clipboard_policy": self._normalize_clipboard_policy(data_dict.get("clipboard_policy", "allow")),
            "totp_secret": str(data_dict.get("totp_secret", "")).strip(),
            "sharing_metadata": self._normalize_sharing_metadata(data_dict.get("sharing_metadata")),
        }

        if not normalized["title"]:
            raise ValueError("Entry title is required")
        if not normalized["password"]:
            raise ValueError("Entry password is required")

        return normalized

    def _normalize_tags(self, raw_tags: Any) -> str:
        if isinstance(raw_tags, list):
            return ",".join(str(tag).strip() for tag in raw_tags if str(tag).strip())
        return str(raw_tags or "").strip()

    def _normalize_sharing_metadata(self, raw_metadata: Any) -> Dict[str, Any]:
        if isinstance(raw_metadata, dict):
            return dict(raw_metadata)
        return {}

    def _normalize_clipboard_policy(self, raw_policy: Any) -> str:
        normalized = str(raw_policy or "allow").strip().lower()
        if normalized not in {"allow", "never"}:
            return "allow"
        return normalized

    def _parse_search_query(self, search_text: str):
        field_aliases = {
            "title": "title",
            "user": "username",
            "username": "username",
            "category": "category",
            "tag": "tags",
            "tags": "tags",
            "url": "url",
            "notes": "notes",
        }
        general_terms = []
        field_filters = []

        for raw_token in search_text.split():
            field_name, separator, raw_value = raw_token.partition(":")
            if separator and field_name in field_aliases and raw_value:
                field_filters.append((field_aliases[field_name], raw_value))
            else:
                general_terms.append(raw_token)

        return general_terms, field_filters

    def _matches_field_filters(self, entry: Dict[str, Any], field_filters) -> bool:
        for field_name, expected_value in field_filters:
            field_value = self._entry_search_value(entry, field_name)
            if not self._matches_search_term(expected_value, field_value):
                return False
        return True

    def _matches_general_terms(self, entry: Dict[str, Any], general_terms) -> bool:
        if not general_terms:
            return True

        haystack = " ".join(
            [
                self._entry_search_value(entry, "title"),
                self._entry_search_value(entry, "username"),
                self._entry_search_value(entry, "category"),
                self._entry_search_value(entry, "tags"),
                self._entry_search_value(entry, "url"),
                self._entry_search_value(entry, "notes"),
            ]
        )
        return all(self._matches_search_term(term, haystack) for term in general_terms)

    def _matches_tag_filter(self, entry: Dict[str, Any], selected_tag: str) -> bool:
        if selected_tag in {"", "все"}:
            return True
        entry_tags = self._split_tags(entry.get("tags", ""))
        return any(self._matches_search_term(selected_tag, tag) for tag in entry_tags)

    def _matches_updated_range(
        self,
        entry: Dict[str, Any],
        updated_from: Optional[datetime],
        updated_to: Optional[datetime],
    ) -> bool:
        updated_at = entry.get("updated_at")
        if not isinstance(updated_at, datetime):
            return updated_from is None and updated_to is None
        if updated_from is not None and updated_at < updated_from:
            return False
        if updated_to is not None and updated_at > updated_to:
            return False
        return True

    def _matches_password_strength(self, entry: Dict[str, Any], selected_strength: str) -> bool:
        if selected_strength in {"", "все"}:
            return True

        strength_label = self._get_password_strength_label(str(entry.get("password", "")))
        strength_aliases = {
            "слабый": "weak",
            "weak": "weak",
            "средний": "medium",
            "medium": "medium",
            "сильный": "strong",
            "strong": "strong",
        }
        return strength_label == strength_aliases.get(selected_strength, selected_strength)

    def _normalize_filter_date(self, raw_value: Any, is_end: bool) -> Optional[datetime]:
        if isinstance(raw_value, datetime):
            return raw_value
        if isinstance(raw_value, date):
            boundary = time.max if is_end else time.min
            return datetime.combine(raw_value, boundary)

        value = str(raw_value or "").strip()
        if not value:
            return None

        try:
            parsed_date = datetime.strptime(value, "%Y-%m-%d").date()
        except ValueError:
            return None

        boundary = time.max if is_end else time.min
        return datetime.combine(parsed_date, boundary)

    def _get_password_strength_label(self, password: str) -> str:
        score = self.password_validator.get_strength_score(password)
        if score < 40:
            return "weak"
        if score < 70:
            return "medium"
        return "strong"

    def _entry_search_value(self, entry: Dict[str, Any], field_name: str) -> str:
        if field_name == "tags":
            return " ".join(self._split_tags(entry.get("tags", ""))).lower()
        return str(entry.get(field_name, "")).lower()

    def _matches_search_term(self, term: str, haystack: str) -> bool:
        normalized_term = str(term or "").strip().lower()
        if not normalized_term:
            return True

        normalized_haystack = str(haystack or "").lower()
        if normalized_term in normalized_haystack:
            return True

        if len(normalized_term) < 4:
            return False

        tokens = self._tokenize_search_text(normalized_haystack)
        return any(self._is_fuzzy_match(normalized_term, token) for token in tokens)

    def _tokenize_search_text(self, value: str) -> List[str]:
        return [token for token in re.split(r"[^a-zа-я0-9_@.-]+", value.lower()) if token]

    def _is_fuzzy_match(self, term: str, token: str) -> bool:
        if abs(len(term) - len(token)) > 2:
            return False
        return SequenceMatcher(None, term, token).ratio() >= self.FUZZY_MATCH_THRESHOLD

    def _rebuild_search_index(self, entries: List[Dict[str, Any]]):
        self.search_index.replace_scope(
            "entries",
            ((entry["id"], self._search_index_fields(entry)) for entry in entries),
        )
        self._search_index_ready = True

    def _update_search_index_entry(self, entry: Dict[str, Any]):
        self.search_index.index_document(entry["id"], self._search_index_fields(entry), scope="entries")
        self._search_index_ready = True

    def _remove_search_index_entry(self, entry_id: int):
        self.search_index.remove_document(entry_id, scope="entries")

    def _search_index_fields(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "title": entry.get("title", ""),
            "username": entry.get("username", ""),
            "category": entry.get("category", ""),
            "tags": " ".join(self._split_tags(entry.get("tags", ""))),
            "url": entry.get("url", ""),
            "notes": entry.get("notes", ""),
        }

    def _candidate_entry_ids_for_search(self, general_terms, field_filters, selected_tag: str) -> Optional[set[int]]:
        candidate_ids: Optional[set[int]] = None

        if selected_tag:
            candidate_ids = self.search_index.search(selected_tag, fields=["tags"], scope="entries")

        for term in general_terms:
            current_ids = self.search_index.search(term, scope="entries")
            if not current_ids:
                return None
            candidate_ids = current_ids if candidate_ids is None else candidate_ids & current_ids

        for field_name, expected_value in field_filters:
            current_ids = self.search_index.search(expected_value, fields=[field_name], scope="entries")
            if not current_ids:
                return None
            candidate_ids = current_ids if candidate_ids is None else candidate_ids & current_ids

        return candidate_ids

    def _split_tags(self, raw_tags: Any) -> List[str]:
        return [tag.strip().lower() for tag in str(raw_tags or "").split(",") if tag.strip()]

    def _encrypt_payload(self, data_dict: Dict[str, Any], created_at: datetime) -> bytes:
        payload = {
            "title": data_dict["title"],
            "username": data_dict["username"],
            "password": data_dict["password"],
            "url": data_dict["url"],
            "notes": data_dict["notes"],
            "category": data_dict["category"],
            "clipboard_policy": data_dict["clipboard_policy"],
            "totp_secret": data_dict["totp_secret"],
            "sharing_metadata": data_dict["sharing_metadata"],
            "version": self.PAYLOAD_VERSION,
            "created_at": created_at.isoformat(),
        }
        plaintext = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        return self.encryption_service.encrypt(plaintext)

    def _deserialize_entry(self, entry) -> Dict[str, Any]:
        payload = self._decrypt_payload(entry)  #если расшифровка не удалась, будет выброшено исключение, которое может быть перехвачено для обработки устаревших данных
        return {
            "id": entry.id,
            "title": payload.get("title", entry.title),
            "username": payload.get("username", entry.username),
            "password": payload.get("password", ""),
            "url": payload.get("url", entry.url),
            "notes": payload.get("notes", entry.notes),
            "category": payload.get("category", ""),
            "clipboard_policy": self._normalize_clipboard_policy(payload.get("clipboard_policy", "allow")),
            "totp_secret": payload.get("totp_secret", ""),
            "sharing_metadata": self._normalize_sharing_metadata(payload.get("sharing_metadata")),
            "version": payload.get("version", self.PAYLOAD_VERSION),
            "tags": entry.tags,
            "created_at": entry.created_at,
            "updated_at": entry.updated_at,
        }

    def _decrypt_payload(self, entry) -> Dict[str, Any]:  #метод для расшифровки данных записи, который пытается расшифровать данные с помощью службы шифрования
        encrypted_payload = entry.encrypted_data or entry.encrypted_password
        try:
            plaintext = self.encryption_service.decrypt(encrypted_payload)
            data = json.loads(plaintext.decode("utf-8"))
            if not isinstance(data, dict):
                raise ValueError("Entry payload must be a JSON object")
            return data
        except (VaultEncryptionError, ValueError, json.JSONDecodeError, UnicodeDecodeError):
            if self.legacy_encryption_service is None:
                raise
            password = self.legacy_encryption_service.decrypt(entry.encrypted_password).decode("utf-8")
            return {
                "title": entry.title,
                "username": entry.username,
                "password": password,
                "url": entry.url,
                "notes": entry.notes,
                "category": entry.category,
                "clipboard_policy": "allow",
                "totp_secret": "",
                "sharing_metadata": {},
                "version": self.PAYLOAD_VERSION,
            }

    def _default_soft_delete_expiration(self) -> datetime:
        return (datetime.now() + timedelta(days=30)).replace(microsecond=0)

    def _publish_search_event(self, *, query: str, category: str, tag: str, result_count: int):
        normalized_query = str(query or "").strip().lower()
        query_hash = hashlib.sha256(normalized_query.encode("utf-8")).hexdigest() if normalized_query else ""
        event_bus.publish(
            Event(
                EventType.SEARCH_PERFORMED,
                {
                    "query_hash": query_hash,
                    "query_length": len(normalized_query),
                    "category": category or "",
                    "tag": tag or "",
                    "result_count": result_count,
                },
            )
        )