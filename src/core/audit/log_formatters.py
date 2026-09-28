from base64 import b64decode, b64encode
import csv
import io
import json
from datetime import datetime, timezone
from typing import Iterable


def export_logs_to_json(logs: Iterable, public_key: str = "", exporter: str = "CryptoSafe Manager") -> str:
    serialized_entries = [serialize_log(log) for log in logs]
    payload = {
        "metadata": {
            "exported_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "exporter": exporter,
            "public_key": public_key,
            "entry_count": len(serialized_entries),
            "sequence_range": _build_sequence_range(serialized_entries),
        },
        "entries": serialized_entries,
    }
    return json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)


def export_logs_to_csv(logs: Iterable) -> str:
    buffer = io.StringIO()
    writer = csv.DictWriter(
        buffer,
        fieldnames=[
            "sequence_number",
            "timestamp",
            "event_type",
            "severity",
            "user_id",
            "source",
            "entry_id",
            "details",
            "previous_hash",
            "entry_hash",
            "signature",
            "public_key",
        ],
    )
    writer.writeheader()
    for log in logs:
        writer.writerow(serialize_log(log))
    return buffer.getvalue()


def export_logs_to_pdf(logs: Iterable, title: str = "CryptoSafe Audit Report") -> bytes:
    lines = [title, ""]
    for log in logs:
        payload = serialize_log(log)
        lines.append(
            f"{payload['sequence_number']} | {payload['timestamp']} | {payload['event_type']} | {payload['severity']}"
        )
        lines.append(f"source={payload['source']} user={payload['user_id']} entry_id={payload['entry_id']}")
        lines.append(f"details={payload['details']}")
        lines.append("")
    content = "\n".join(lines).replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
    pdf = (
        "%PDF-1.4\n"
        "1 0 obj<< /Type /Catalog /Pages 2 0 R >>endobj\n"
        "2 0 obj<< /Type /Pages /Count 1 /Kids [3 0 R] >>endobj\n"
        "3 0 obj<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>endobj\n"
        f"4 0 obj<< /Length {len(content) + 20} >>stream\nBT /F1 10 Tf 40 760 Td ({content}) Tj ET\nendstream endobj\n"
        "xref\n0 5\n0000000000 65535 f \n"
        "trailer<< /Size 5 /Root 1 0 R >>\nstartxref\n0\n%%EOF"
    )
    return pdf.encode("utf-8")


def export_logs_to_cef(logs: Iterable, device_vendor: str = "CryptoSafe", device_product: str = "Manager") -> str:
    lines = []
    for log in logs:
        payload = serialize_log(log)
        event_type = str(payload["event_type"] or "audit_event")
        severity = _map_cef_severity(str(payload["severity"] or "INFO"))
        details = _normalize_cef_details(payload.get("details", ""))
        extensions = {
            "rt": payload["timestamp"],
            "suser": payload["user_id"],
            "cs1Label": "source",
            "cs1": payload["source"],
            "cn1Label": "sequence_number",
            "cn1": payload["sequence_number"],
            "cs2Label": "previous_hash",
            "cs2": payload["previous_hash"],
            "cs3Label": "entry_hash",
            "cs3": payload["entry_hash"],
            "deviceCustomNumber1Label": "entry_id",
            "deviceCustomNumber1": payload["entry_id"] if payload["entry_id"] is not None else "",
            "msg": details,
        }
        line = (
            f"CEF:0|{_escape_cef_header(device_vendor)}|{_escape_cef_header(device_product)}|5|"
            f"{_escape_cef_header(event_type)}|{_escape_cef_header(event_type)}|{severity}|"
            f"{_format_cef_extensions(extensions)}"
        )
        lines.append(line)
    return "\n".join(lines)


def serialize_log(log) -> dict:
    timestamp = getattr(log, "timestamp", "")
    if hasattr(timestamp, "isoformat"):
        timestamp = timestamp.isoformat()
    return {
        "sequence_number": getattr(log, "sequence_number", getattr(log, "id", "")),
        "timestamp": timestamp,
        "event_type": getattr(log, "event_type", getattr(log, "action", "")),
        "severity": getattr(log, "severity", "INFO"),
        "user_id": getattr(log, "user_id", "local-user"),
        "source": getattr(log, "source", "unknown"),
        "entry_id": getattr(log, "entry_id", None),
        "details": getattr(log, "details", ""),
        "previous_hash": getattr(log, "previous_hash", ""),
        "entry_hash": getattr(log, "entry_hash", ""),
        "entry_data": getattr(log, "entry_data", ""),
        "signature": getattr(log, "signature", ""),
        "public_key": getattr(log, "public_key", ""),
    }


def import_logs_from_json(payload: str) -> list[dict]:
    parsed = json.loads(payload)
    entries = parsed.get("entries", [])
    if not isinstance(entries, list):
        raise ValueError("Экспорт журнала аудита содержит некорректный список записей")
    normalized_entries = []
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("Каждая запись экспорта должна быть объектом")
        normalized_entries.append(dict(entry))
    return normalized_entries


def _build_sequence_range(entries: list[dict]) -> dict:
    if not entries:
        return {"from": None, "to": None}
    sequences = [int(entry.get("sequence_number", 0) or 0) for entry in entries]
    return {"from": min(sequences), "to": max(sequences)}


def encrypt_export_package(
    payload,
    *,
    export_format: str,
    encryption_service,
    key: bytes,
    exporter: str = "CryptoSafe Manager",
) -> bytes:
    payload_bytes = payload if isinstance(payload, bytes) else str(payload).encode("utf-8")
    ciphertext = encryption_service.encrypt(payload_bytes, key)
    package = {
        "metadata": {
            "encrypted": True,
            "algorithm": "AES-256-GCM",
            "content_format": str(export_format or "").strip().lower(),
            "exported_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "exporter": exporter,
        },
        "ciphertext": b64encode(ciphertext).decode("ascii"),
    }
    return json.dumps(package, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8")


def decrypt_export_package(
    package_payload,
    *,
    encryption_service,
    key: bytes,
) -> dict:
    raw_bytes = package_payload if isinstance(package_payload, bytes) else str(package_payload).encode("utf-8")
    parsed = json.loads(raw_bytes.decode("utf-8"))
    metadata = parsed.get("metadata", {})
    ciphertext = parsed.get("ciphertext", "")
    if not metadata.get("encrypted") or not ciphertext:
        raise ValueError("Export package is not encrypted")
    plaintext = encryption_service.decrypt(b64decode(ciphertext), key)
    return {
        "metadata": metadata,
        "payload": plaintext,
        "content_format": metadata.get("content_format", ""),
    }


def _map_cef_severity(severity: str) -> int:
    mapping = {"INFO": 3, "WARN": 5, "ERROR": 8, "CRITICAL": 10}
    return mapping.get(str(severity or "").upper(), 3)


def _normalize_cef_details(details) -> str:
    if isinstance(details, dict):
        return json.dumps(details, ensure_ascii=False, sort_keys=True)
    return str(details or "")


def _escape_cef_header(value: str) -> str:
    return str(value or "").replace("\\", "\\\\").replace("|", "\\|")


def _escape_cef_extension(value) -> str:
    return str(value or "").replace("\\", "\\\\").replace("=", "\\=").replace("\n", "\\n").replace("\r", "")


def _format_cef_extensions(extensions: dict) -> str:
    parts = []
    for key, value in extensions.items():
        if value == "":
            continue
        parts.append(f"{key}={_escape_cef_extension(value)}")
    return " ".join(parts)