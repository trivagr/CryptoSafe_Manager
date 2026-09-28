import base64
import hashlib
import hmac
import html
import io
import json
import os
import time
import zlib
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

from ..events import Event, EventType
from ..security.side_channel_protection import constant_time_compare
from .crypto import generate_ec_key_pair, generate_rsa_key_pair, public_key_fingerprint
from .exceptions import ImportValidationError


QR_PAYLOAD_VERSION = 1
QR_PAYLOAD_TTL_SECONDS = 5 * 60


@dataclass(frozen=True)
class KeyExchangePayload:
    identifier: str
    public_key: str
    fingerprint: str
    nonce: str
    created_at: str
    expires_at: str
    checksum: str


class KeyExchangeService:
    def __init__(self, database=None, event_bus=None):
        self.database = database
        self.event_bus = event_bus
        self._seen_nonces: set[str] = set()

    def fingerprint_public_key(self, public_key: str) -> str:
        return public_key_fingerprint(public_key)

    def generate_key_pair(self, algorithm: str = "RSA-2048") -> Dict[str, str]:
        normalized_algorithm = str(algorithm or "RSA-2048").upper()
        if normalized_algorithm in {"ECC", "EC", "P-256", "ECC-P256"}:
            private_key, public_key = generate_ec_key_pair()
            algorithm_name = "ECC-P256"
        else:
            private_key, public_key = generate_rsa_key_pair()
            algorithm_name = "RSA-2048"
        return {
            "algorithm": algorithm_name,
            "private_key": private_key,
            "public_key": public_key,
            "fingerprint": self.fingerprint_public_key(public_key),
        }

    def build_qr_payload(self, *, identifier: str, public_key: str) -> Dict[str, Any]:
        now = datetime.now(timezone.utc)
        payload = {
            "type": "cryptosafe_key_exchange",
            "version": QR_PAYLOAD_VERSION,
            "identifier": str(identifier),
            "public_key": str(public_key),
            "fingerprint": self.fingerprint_public_key(public_key),
            "nonce": base64.urlsafe_b64encode(os.urandom(16)).decode("ascii").rstrip("="),
            "created_at": now.isoformat(),
            "expires_at": (now + timedelta(seconds=QR_PAYLOAD_TTL_SECONDS)).isoformat(),
        }
        payload["checksum"] = self._checksum(payload)
        self._publish(EventType.KEY_EXCHANGE_CREATED, {"identifier": payload["identifier"], "fingerprint": payload["fingerprint"]})
        return payload

    def build_data_qr_payload(self, *, payload_type: str, label: str, data: str, ttl_seconds: int = QR_PAYLOAD_TTL_SECONDS) -> Dict[str, Any]:
        now = datetime.now(timezone.utc)
        normalized_type = str(payload_type or "cryptosafe_encrypted_data").strip()
        if normalized_type not in {"cryptosafe_encrypted_entry", "cryptosafe_share_package", "cryptosafe_share_link"}:
            normalized_type = "cryptosafe_encrypted_data"
        payload = {
            "type": normalized_type,
            "version": QR_PAYLOAD_VERSION,
            "label": str(label or ""),
            "data": str(data or ""),
            "nonce": base64.urlsafe_b64encode(os.urandom(16)).decode("ascii").rstrip("="),
            "created_at": now.isoformat(),
            "expires_at": (now + timedelta(seconds=max(30, int(ttl_seconds)))).isoformat(),
        }
        payload["checksum"] = self._checksum(payload)
        return payload

    def serialize_qr_payload(self, payload: Dict[str, Any]) -> str:
        self.validate_any_qr_payload(payload)
        return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))

    def parse_data_qr_payload(self, raw_payload: str) -> Dict[str, Any]:
        try:
            payload = json.loads(raw_payload)
        except json.JSONDecodeError as exc:
            raise ImportValidationError("QR payload is not valid JSON") from exc
        self.validate_data_qr_payload(payload)
        self._remember_nonce(str(payload["nonce"]))
        return payload

    def parse_qr_payload(self, raw_payload: str) -> KeyExchangePayload:
        try:
            payload = json.loads(raw_payload)
        except json.JSONDecodeError as exc:
            raise ImportValidationError("QR payload is not valid JSON") from exc
        self.validate_qr_payload(payload)
        self._remember_nonce(str(payload["nonce"]))
        return KeyExchangePayload(
            identifier=str(payload["identifier"]),
            public_key=str(payload["public_key"]),
            fingerprint=str(payload["fingerprint"]),
            nonce=str(payload["nonce"]),
            created_at=str(payload["created_at"]),
            expires_at=str(payload["expires_at"]),
            checksum=str(payload["checksum"]),
        )

    def remember_contact(self, payload: KeyExchangePayload, *, name: str = "") -> int | None:
        if self.database is None:
            return None
        contact_id = self.database.upsert_contact(
            name=name or payload.identifier,
            identifier=payload.identifier,
            public_key=payload.public_key,
            key_fingerprint=payload.fingerprint,
            last_used_at=datetime.now(timezone.utc),
        )
        self._publish(EventType.KEY_EXCHANGE_IMPORTED, {"identifier": payload.identifier, "fingerprint": payload.fingerprint})
        return contact_id

    def rotate_contact_key(self, *, identifier: str, public_key: str, name: str = "") -> int | None:
        payload = self.build_qr_payload(identifier=identifier, public_key=public_key)
        parsed = self.parse_qr_payload(self.serialize_qr_payload(payload))
        return self.remember_contact(parsed, name=name)

    def revoke_contact(self, identifier: str) -> bool:
        if self.database is None:
            return False
        return self.database.revoke_contact(identifier)

    def split_qr_payload(self, raw_payload: str, *, max_chunk_size: int = 512) -> List[str]:
        payload = str(raw_payload)
        encoded_payload = base64.b64encode(zlib.compress(payload.encode("utf-8"))).decode("ascii")
        chunk_size = max(128, int(max_chunk_size))
        chunks = [encoded_payload[index:index + chunk_size] for index in range(0, len(encoded_payload), chunk_size)] or [""]
        transfer_id = base64.urlsafe_b64encode(os.urandom(8)).decode("ascii").rstrip("=")
        full_checksum = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        return [
            json.dumps(
                {
                    "type": "cryptosafe_qr_chunk",
                    "version": QR_PAYLOAD_VERSION,
                    "transfer_id": transfer_id,
                    "index": index,
                    "total": len(chunks),
                    "checksum": full_checksum,
                    "encoding": "zlib+base64",
                    "data": chunk,
                },
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            for index, chunk in enumerate(chunks)
        ]

    def assemble_qr_chunks(self, raw_chunks: List[str]) -> str:
        chunks = []
        for raw_chunk in raw_chunks:
            try:
                parsed = json.loads(raw_chunk)
            except json.JSONDecodeError as exc:
                raise ImportValidationError("QR chunk is not valid JSON") from exc
            if parsed.get("type") != "cryptosafe_qr_chunk":
                raise ImportValidationError("QR chunk type is not supported")
            chunks.append(parsed)
        if not chunks:
            raise ImportValidationError("QR chunks are empty")
        transfer_ids = {chunk.get("transfer_id") for chunk in chunks}
        totals = {int(chunk.get("total", 0)) for chunk in chunks}
        checksums = {chunk.get("checksum") for chunk in chunks}
        if len(transfer_ids) != 1 or len(totals) != 1 or len(checksums) != 1:
            raise ImportValidationError("QR chunks belong to different transfers")
        total = totals.pop()
        if total != len(chunks):
            raise ImportValidationError("QR chunks are incomplete")
        ordered = sorted(chunks, key=lambda chunk: int(chunk.get("index", -1)))
        if [int(chunk.get("index", -1)) for chunk in ordered] != list(range(total)):
            raise ImportValidationError("QR chunks are out of sequence")
        payload = "".join(str(chunk.get("data", "")) for chunk in ordered)
        if str(ordered[0].get("encoding", "")) == "zlib+base64":
            try:
                payload = zlib.decompress(base64.b64decode(payload.encode("ascii"), validate=True)).decode("utf-8")
            except Exception as exc:
                raise ImportValidationError("QR chunk compressed payload is invalid") from exc
        expected_checksum = checksums.pop()
        if not constant_time_compare(hashlib.sha256(payload.encode("utf-8")).hexdigest(), str(expected_checksum)):
            raise ImportValidationError("QR chunk checksum does not match")
        return payload

    def validate_qr_payload(self, payload: Dict[str, Any]):
        if not isinstance(payload, dict):
            raise ImportValidationError("QR payload must be an object")
        required_fields = {
            "type",
            "version",
            "identifier",
            "public_key",
            "fingerprint",
            "nonce",
            "created_at",
            "expires_at",
            "checksum",
        }
        missing = sorted(required_fields.difference(payload))
        if missing:
            raise ImportValidationError(f"QR payload is missing fields: {', '.join(missing)}")
        if payload["type"] != "cryptosafe_key_exchange":
            raise ImportValidationError("QR payload type is not supported")
        if int(payload["version"]) != QR_PAYLOAD_VERSION:
            raise ImportValidationError("QR payload version is not supported")
        if self.fingerprint_public_key(str(payload["public_key"])) != str(payload["fingerprint"]):
            raise ImportValidationError("QR public key fingerprint does not match")
        if not hmac_compare(str(payload["checksum"]), self._checksum(payload)):
            raise ImportValidationError("QR payload checksum does not match")

        expires_at = datetime.fromisoformat(str(payload["expires_at"]))
        if expires_at < datetime.now(timezone.utc):
            raise ImportValidationError("QR payload has expired")
        if str(payload["nonce"]) in self._seen_nonces:
            raise ImportValidationError("QR payload nonce has already been used")

    def validate_data_qr_payload(self, payload: Dict[str, Any]):
        if not isinstance(payload, dict):
            raise ImportValidationError("QR payload must be an object")
        required_fields = {"type", "version", "label", "data", "nonce", "created_at", "expires_at", "checksum"}
        missing = sorted(required_fields.difference(payload))
        if missing:
            raise ImportValidationError(f"QR payload is missing fields: {', '.join(missing)}")
        if payload["type"] not in {"cryptosafe_encrypted_entry", "cryptosafe_share_package", "cryptosafe_share_link", "cryptosafe_encrypted_data"}:
            raise ImportValidationError("QR payload type is not supported")
        if int(payload["version"]) != QR_PAYLOAD_VERSION:
            raise ImportValidationError("QR payload version is not supported")
        if not hmac_compare(str(payload["checksum"]), self._checksum(payload)):
            raise ImportValidationError("QR payload checksum does not match")
        expires_at = datetime.fromisoformat(str(payload["expires_at"]))
        if expires_at < datetime.now(timezone.utc):
            raise ImportValidationError("QR payload has expired")
        if str(payload["nonce"]) in self._seen_nonces:
            raise ImportValidationError("QR payload nonce has already been used")

    def validate_any_qr_payload(self, payload: Dict[str, Any]):
        if isinstance(payload, dict) and payload.get("type") == "cryptosafe_key_exchange":
            return self.validate_qr_payload(payload)
        return self.validate_data_qr_payload(payload)

    def _checksum(self, payload: Dict[str, Any]) -> str:
        unsigned = {key: value for key, value in payload.items() if key != "checksum"}
        encoded = json.dumps(unsigned, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(encoded.encode("utf-8")).hexdigest()

    def _remember_nonce(self, nonce: str):
        self._seen_nonces.add(str(nonce))

    def _publish(self, event_type: EventType, data: Dict[str, Any]):
        if self.event_bus is not None:
            self.event_bus.publish(Event(event_type, data))


def hmac_compare(left: str, right: str) -> bool:
    return constant_time_compare(str(left), str(right))


class QRCodeService:
    _segno_backend = None

    def __init__(self, key_exchange: KeyExchangeService | None = None, *, error_correction: str = "M", camera_scanner=None):
        self.key_exchange = key_exchange or KeyExchangeService()
        self.error_correction = str(error_correction or "M").upper()
        self.camera_scanner = camera_scanner
        self._ensure_qr_backend()

    def generate_qr_svgs(self, raw_payload: str, *, max_chunk_size: int = 1024) -> List[str]:
        chunks = self.key_exchange.split_qr_payload(raw_payload, max_chunk_size=max_chunk_size)
        return [self._chunk_to_svg(chunk) for chunk in chunks]

    def generate_qr_pngs(self, raw_payload: str, *, max_chunk_size: int = 1024, scale: int = 6) -> List[bytes]:
        chunks = self.key_exchange.split_qr_payload(raw_payload, max_chunk_size=max_chunk_size)
        return [self._chunk_to_png(chunk, scale=scale) for chunk in chunks]

    def parse_qr_svgs(self, svg_payloads: List[str]) -> str:
        chunks = [self._extract_chunk_from_svg(svg) for svg in svg_payloads]
        return self.key_exchange.assemble_qr_chunks(chunks)

    def parse_qr_svg_files(self, file_paths: List[str]) -> str:
        svg_payloads = []
        for file_path in file_paths:
            with open(file_path, "r", encoding="utf-8") as handle:
                svg_payloads.append(handle.read())
        return self.parse_qr_svgs(svg_payloads)

    def scan_from_camera(self) -> str:
        if self.camera_scanner is None:
            raise ImportValidationError("Device camera scanning is unavailable in this environment; use QR image file upload")
        try:
            scanned_payload = self.camera_scanner()
        except Exception as exc:
            raise ImportValidationError("QR camera scan failed; use QR image file upload") from exc
        if isinstance(scanned_payload, list):
            return self.key_exchange.assemble_qr_chunks([str(item) for item in scanned_payload])
        scanned_text = str(scanned_payload or "")
        if not scanned_text:
            raise ImportValidationError("QR camera scan did not return payload data")
        return scanned_text

    def generate_key_exchange_svgs(self, *, identifier: str, public_key: str, max_chunk_size: int = 1024) -> List[str]:
        raw_payload = self.key_exchange.serialize_qr_payload(
            self.key_exchange.build_qr_payload(identifier=identifier, public_key=public_key)
        )
        return self.generate_qr_svgs(raw_payload, max_chunk_size=max_chunk_size)

    def generate_key_exchange_pngs(self, *, identifier: str, public_key: str, max_chunk_size: int = 1024, scale: int = 6) -> List[bytes]:
        raw_payload = self.key_exchange.serialize_qr_payload(
            self.key_exchange.build_qr_payload(identifier=identifier, public_key=public_key)
        )
        return self.generate_qr_pngs(raw_payload, max_chunk_size=max_chunk_size, scale=scale)

    def generate_data_payload_svgs(
        self,
        *,
        payload_type: str,
        label: str,
        data: str,
        max_chunk_size: int = 1024,
    ) -> List[str]:
        raw_payload = self.key_exchange.serialize_qr_payload(
            self.key_exchange.build_data_qr_payload(payload_type=payload_type, label=label, data=data)
        )
        return self.generate_qr_svgs(raw_payload, max_chunk_size=max_chunk_size)

    def generate_data_payload_pngs(
        self,
        *,
        payload_type: str,
        label: str,
        data: str,
        max_chunk_size: int = 1024,
        scale: int = 6,
    ) -> List[bytes]:
        raw_payload = self.key_exchange.serialize_qr_payload(
            self.key_exchange.build_data_qr_payload(payload_type=payload_type, label=label, data=data)
        )
        return self.generate_qr_pngs(raw_payload, max_chunk_size=max_chunk_size, scale=scale)

    def parse_key_exchange_svgs(self, svg_payloads: List[str]) -> KeyExchangePayload:
        return self.key_exchange.parse_qr_payload(self.parse_qr_svgs(svg_payloads))

    def benchmark_generation(self, raw_payload: str, *, max_chunk_size: int = 1024) -> Dict[str, Any]:
        started = time.perf_counter()
        svgs = self.generate_qr_svgs(raw_payload, max_chunk_size=max_chunk_size)
        return {
            "elapsed_seconds": time.perf_counter() - started,
            "qr_count": len(svgs),
            "total_bytes": sum(len(svg.encode("utf-8")) for svg in svgs),
        }

    def _chunk_to_svg(self, chunk: str) -> str:
        metadata = html.escape(chunk, quote=True)
        segno = self._ensure_qr_backend()
        qr = segno.make(chunk, error=self.error_correction.lower(), micro=False)
        output = io.BytesIO()
        qr.save(output, kind="svg", scale=4, border=4)
        svg = output.getvalue().decode("utf-8")
        return svg.replace(
            "<svg ",
            f'<svg data-cryptosafe-qr="1" data-error-correction="{html.escape(self.error_correction)}" ',
            1,
        ).replace("</svg>", f"<metadata>{metadata}</metadata></svg>", 1)

    def _chunk_to_png(self, chunk: str, *, scale: int = 6) -> bytes:
        segno = self._ensure_qr_backend()
        qr = segno.make(chunk, error=self.error_correction.lower(), micro=False)
        output = io.BytesIO()
        qr.save(output, kind="png", scale=max(2, int(scale)), border=4)
        return output.getvalue()

    def _ensure_qr_backend(self):
        if self.__class__._segno_backend is not None:
            return self.__class__._segno_backend
        try:
            import segno
        except Exception as exc:
            raise ImportValidationError(
                "QR generation requires the segno package. Install dependencies with: py -m pip install -r requirements.txt"
            ) from exc
        self.__class__._segno_backend = segno
        return segno

    def _extract_chunk_from_svg(self, svg_payload: str) -> str:
        text = str(svg_payload or "")
        start = text.find("<metadata>")
        end = text.find("</metadata>")
        if start < 0 or end <= start:
            raise ImportValidationError("QR image does not contain CryptoSafe payload metadata")
        return html.unescape(text[start + len("<metadata>"):end])