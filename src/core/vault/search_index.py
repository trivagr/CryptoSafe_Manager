import re
from collections import defaultdict
from typing import Any, Dict, Iterable, List, Optional, Set


class SearchIndex:
    def __init__(self):
        self._documents: Dict[str, Dict[Any, Dict[str, str]]] = defaultdict(dict)
        self._field_tokens: Dict[str, Dict[str, Dict[str, Set[Any]]]] = defaultdict(
            lambda: defaultdict(lambda: defaultdict(set))
        )

    def replace_scope(self, scope: str, documents: Iterable[tuple[Any, Dict[str, Any]]]):
        self.clear_scope(scope)
        for document_id, fields in documents:
            self.index_document(document_id, fields, scope=scope)

    def clear_scope(self, scope: str):
        for field_name, token_map in self._field_tokens.get(scope, {}).items():
            for token in list(token_map):
                token_map[token].clear()
            self._field_tokens[scope][field_name].clear()
        self._documents[scope].clear()

    def index_document(self, document_id: Any, fields: Dict[str, Any], scope: str = "entries"):
        self.remove_document(document_id, scope=scope)

        normalized_fields = {
            str(field_name): str(field_value or "").strip().lower()
            for field_name, field_value in fields.items()
        }
        self._documents[scope][document_id] = normalized_fields

        for field_name, field_value in normalized_fields.items():
            for token in self._tokenize(field_value):
                self._field_tokens[scope][field_name][token].add(document_id)

    def remove_document(self, document_id: Any, scope: str = "entries"):
        existing_fields = self._documents.get(scope, {}).pop(document_id, None)
        if existing_fields is None:
            return

        for field_name, field_value in existing_fields.items():
            token_map = self._field_tokens[scope][field_name]
            for token in self._tokenize(field_value):
                document_ids = token_map.get(token)
                if not document_ids:
                    continue
                document_ids.discard(document_id)
                if not document_ids:
                    token_map.pop(token, None)

    def search(self, term: str, fields: Optional[List[str]] = None, scope: str = "entries") -> Set[Any]:
        normalized_term = str(term or "").strip().lower()
        if not normalized_term:
            return set(self._documents.get(scope, {}))

        search_fields = fields or list(self._field_tokens.get(scope, {}))
        matched_ids: Set[Any] = set()
        for field_name in search_fields:
            matched_ids.update(self._field_tokens.get(scope, {}).get(field_name, {}).get(normalized_term, set()))
        return matched_ids

    def _tokenize(self, value: str) -> List[str]:
        return [token for token in re.split(r"[^a-zа-я0-9_@.-]+", value.lower()) if token]