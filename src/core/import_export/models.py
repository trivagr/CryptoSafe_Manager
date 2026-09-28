from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class ExportOptions:
    format: str = "encrypted_json"
    entry_ids: Optional[List[int]] = None
    include_fields: Optional[List[str]] = None
    encryption_strength: int = 256
    compression: bool = False
    plaintext_allowed: bool = False


@dataclass
class ImportOptions:
    format: str = "auto"
    mode: str = "dry-run"
    duplicate_strategy: str = "skip"
    max_file_size: int = 10 * 1024 * 1024
    timeout_seconds: int = 30


@dataclass
class SharePermissions:
    read: bool = True
    edit: bool = False
    expires_in_days: int = 7
    extra: Dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "read": bool(self.read),
            "edit": bool(self.edit),
            "expires_in_days": max(1, min(30, int(self.expires_in_days))),
            **dict(self.extra),
        }