import json
from typing import Any, Dict

from ..exceptions import ImportValidationError


class NativeJSONFormat:
    name = "encrypted_json"
    version = "1.0"

    def serialize_header(self, package: Dict[str, Any]) -> str:
        return json.dumps(package, ensure_ascii=False, sort_keys=True)

    def deserialize_header(self, payload: str) -> Dict[str, Any]:
        parsed = json.loads(payload)
        if not isinstance(parsed, dict):
            raise ValueError("Нативный JSON-экспорт должен быть JSON-объектом")
        return parsed

    def is_native_export(self, payload: Dict[str, Any]) -> bool:
        return bool(payload.get("cryptosafe_export"))

    def validate_package(self, package: Dict[str, Any]):
        if not self.is_native_export(package):
            raise ImportValidationError("Файл не является нативным экспортом CryptoSafe")
        required = {"cryptosafe_export", "timestamp", "encryption", "data", "integrity"}
        missing = sorted(required.difference(package))
        if missing:
            raise ImportValidationError(f"В нативном экспорте отсутствуют поля: {', '.join(missing)}")
        if not isinstance(package.get("encryption"), dict):
            raise ImportValidationError("Метаданные шифрования нативного экспорта имеют неверный формат")
        if not isinstance(package.get("data"), dict):
            raise ImportValidationError("Блок данных нативного экспорта имеет неверный формат")
        if not isinstance(package.get("integrity"), dict):
            raise ImportValidationError("Блок целостности нативного экспорта имеет неверный формат")