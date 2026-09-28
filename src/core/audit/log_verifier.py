import hashlib
import json
from typing import Any, Dict, List, Optional


class AuditLogVerifier:
    def __init__(self, database, signer):
        self.database = database
        self.signer = signer

    def verify(self, start_sequence: int = 0, limit: Optional[int] = None) -> Dict[str, Any]:
        try:
            rows = self.database.get_audit_log_chain(start_sequence=start_sequence, limit=limit)
        except Exception as error:
            return {
                "verified": False,
                "total_entries": 0,
                "valid_entries": 0,
                "invalid_entries": [{"reason": "database_error", "message": str(error)}],
                "chain_breaks": [],
                "recovery_options": [
                    "restore_from_backup",
                    "export_verification_report",
                    "rebuild_audit_log",
                ],
            }
        results: Dict[str, Any] = {
            "verified": True,
            "total_entries": len(rows),
            "valid_entries": 0,
            "invalid_entries": [],
            "chain_breaks": [],
            "recovery_options": [
                "restore_from_backup",
                "export_verification_report",
                "rebuild_audit_log",
            ],
        }

        previous_hash = None
        if start_sequence > 1 and rows:
            previous_row = self._get_previous_row(start_sequence)
            if previous_row is not None:
                previous_hash = previous_row.entry_hash
        for row in rows:
            entry_data = row.entry_data or ""
            computed_hash = hashlib.sha256(entry_data.encode("utf-8")).hexdigest()
            if computed_hash != row.entry_hash:
                results["verified"] = False
                results["invalid_entries"].append(
                    {"sequence_number": row.sequence_number, "reason": "hash_mismatch"}
                )
                continue

            if not self._verify_signature(entry_data, row.signature, row.public_key):
                results["verified"] = False
                results["invalid_entries"].append(
                    {"sequence_number": row.sequence_number, "reason": "invalid_signature"}
                )
                continue

            if previous_hash is not None and row.previous_hash != previous_hash:
                results["verified"] = False
                results["chain_breaks"].append(
                    {
                        "sequence_number": row.sequence_number,
                        "expected_previous_hash": previous_hash,
                        "actual_previous_hash": row.previous_hash,
                    }
                )
                continue

            previous_hash = row.entry_hash
            results["valid_entries"] += 1
        return results

    def export_verification_report(self, start_sequence: int = 0, limit: Optional[int] = None) -> str:
        return json.dumps(self.verify(start_sequence=start_sequence, limit=limit), ensure_ascii=False, indent=2)

    def verify_exported_json(self, payload: str) -> Dict[str, Any]:
        try:
            parsed = json.loads(payload)
        except json.JSONDecodeError as error:
            return {
                "verified": False,
                "total_entries": 0,
                "valid_entries": 0,
                "invalid_entries": [{"reason": "invalid_json", "message": str(error)}],
                "chain_breaks": [],
            }

        entries = parsed.get("entries", [])
        if not isinstance(entries, list):
            return {
                "verified": False,
                "total_entries": 0,
                "valid_entries": 0,
                "invalid_entries": [{"reason": "invalid_entries_payload"}],
                "chain_breaks": [],
            }

        results: Dict[str, Any] = {
            "verified": True,
            "total_entries": len(entries),
            "valid_entries": 0,
            "invalid_entries": [],
            "chain_breaks": [],
            "recovery_options": [
                "reexport_audit_log",
                "compare_with_local_database",
                "rebuild_audit_log",
            ],
        }
        previous_hash = None
        for entry in sorted(entries, key=lambda item: int(item.get("sequence_number", 0) or 0)):
            entry_data = str(entry.get("entry_data", "") or "")
            entry_hash = str(entry.get("entry_hash", "") or "")
            previous_entry_hash = str(entry.get("previous_hash", "") or "")
            signature = str(entry.get("signature", "") or "")
            public_key = str(entry.get("public_key", "") or "")
            sequence_number = int(entry.get("sequence_number", 0) or 0)

            if not entry_data:
                canonical_payload = {
                    "timestamp": entry.get("timestamp", ""),
                    "event_type": entry.get("event_type", entry.get("action", "")),
                    "severity": entry.get("severity", "INFO"),
                    "user_id": entry.get("user_id", "local-user"),
                    "source": entry.get("source", "unknown"),
                    "entry_id": entry.get("entry_id"),
                    "details": entry.get("details", {}),
                    "sequence_number": sequence_number,
                    "previous_hash": previous_entry_hash,
                }
                entry_data = json.dumps(canonical_payload, ensure_ascii=False, sort_keys=True)

            computed_hash = hashlib.sha256(entry_data.encode("utf-8")).hexdigest()
            if computed_hash != entry_hash:
                results["verified"] = False
                results["invalid_entries"].append({"sequence_number": sequence_number, "reason": "hash_mismatch"})
                continue

            if not self._verify_signature(entry_data, signature, public_key):
                results["verified"] = False
                results["invalid_entries"].append({"sequence_number": sequence_number, "reason": "invalid_signature"})
                continue

            if previous_hash is not None and previous_entry_hash != previous_hash:
                results["verified"] = False
                results["chain_breaks"].append(
                    {
                        "sequence_number": sequence_number,
                        "expected_previous_hash": previous_hash,
                        "actual_previous_hash": previous_entry_hash,
                    }
                )
                continue

            previous_hash = entry_hash
            results["valid_entries"] += 1
        return results

    def _verify_signature(self, entry_data: str, signature: str, public_key: str) -> bool:
        if signature == "legacy" and public_key == "legacy":
            return True
        return self.signer.verify(entry_data.encode("utf-8"), signature, public_key)

    def _get_previous_row(self, start_sequence: int):
        if not hasattr(self.database, "get_audit_log_by_sequence"):
            return None
        try:
            return self.database.get_audit_log_by_sequence(start_sequence - 1)
        except Exception:
            return None