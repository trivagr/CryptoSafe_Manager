import os
import sys
import unittest
from datetime import datetime

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.core.audit import AuditLogger, AuditLogSigner, AuditLogVerifier
from src.core.events import AuditLoggerStub, Event, EventBus, EventType


class FakeAuditDatabase:
    def __init__(self):
        self.records = []
        self._audit_entry_data_decoder = None

    def get_audit_log_chain(self, start_sequence=0, limit=None):
        rows = list(self.records)
        rows.sort(key=lambda item: item["sequence_number"])
        if start_sequence:
            rows = [row for row in rows if row["sequence_number"] >= start_sequence]
        if limit is not None:
            rows = rows[-limit:]
        return [type("AuditRow", (), self._normalize_row(row)) for row in rows]

    def register_audit_public_key(self, algorithm, public_key):
        self.public_key = {"algorithm": algorithm, "public_key": public_key}

    def get_latest_audit_log(self):
        if not self.records:
            return None
        latest = max(self.records, key=lambda item: item["sequence_number"])
        return type("AuditRow", (), self._normalize_row(latest))

    def set_audit_entry_data_decoder(self, decoder):
        self._audit_entry_data_decoder = decoder

    def add_audit_log(self, action, timestamp, entry_id=None, details="", **kwargs):
        sequence_number = len(self.records) + 1
        self.records.append(
            {
                "id": sequence_number,
                "sequence_number": sequence_number,
                "action": action,
                "event_type": kwargs.get("event_type", action),
                "timestamp": timestamp,
                "severity": kwargs.get("severity", "INFO"),
                "user_id": kwargs.get("user_id", "local-user"),
                "source": kwargs.get("source", "unknown"),
                "entry_id": entry_id,
                "details": details,
                "previous_hash": kwargs.get("previous_hash", ""),
                "entry_hash": kwargs.get("entry_hash", ""),
                "entry_data": kwargs.get("entry_data", ""),
                "signature": kwargs.get("signature", ""),
                "public_key": kwargs.get("public_key", ""),
            }
        )
        return sequence_number

    def _normalize_row(self, row):
        normalized = dict(row)
        if self._audit_entry_data_decoder is not None:
            normalized["entry_data"] = self._audit_entry_data_decoder(normalized.get("entry_data", ""))
        return normalized


class TestEvents(unittest.TestCase):
    def setUp(self):
        self.event_bus = EventBus()
        self.received_events = []

    def test_publish_subscribe(self):
        def callback(event):
            self.received_events.append(event)

        self.event_bus.subscribe(EventType.ENTRY_ADDED, callback)
        self.event_bus.publish(Event(EventType.ENTRY_ADDED, {"id": 1}))

        self.assertEqual(len(self.received_events), 1)
        self.assertEqual(self.received_events[0].type, EventType.ENTRY_ADDED)

    def test_multiple_subscribers(self):
        count1 = 0
        count2 = 0

        def callback1(_event):
            nonlocal count1
            count1 += 1

        def callback2(_event):
            nonlocal count2
            count2 += 1

        self.event_bus.subscribe(EventType.ENTRY_ADDED, callback1)
        self.event_bus.subscribe(EventType.ENTRY_ADDED, callback2)
        self.event_bus.publish(Event(EventType.ENTRY_ADDED, {}))

        self.assertEqual(count1, 1)
        self.assertEqual(count2, 1)

    def test_different_event_types(self):
        added = 0
        deleted = 0
        clipboard_copied = 0

        def on_add(_event):
            nonlocal added
            added += 1

        def on_delete(_event):
            nonlocal deleted
            deleted += 1

        def on_clipboard(_event):
            nonlocal clipboard_copied
            clipboard_copied += 1

        self.event_bus.subscribe(EventType.ENTRY_ADDED, on_add)
        self.event_bus.subscribe(EventType.ENTRY_DELETED, on_delete)
        self.event_bus.subscribe(EventType.CLIPBOARD_COPIED, on_clipboard)

        self.event_bus.publish(Event(EventType.ENTRY_ADDED, {}))
        self.event_bus.publish(Event(EventType.ENTRY_DELETED, {}))
        self.event_bus.publish(Event(EventType.CLIPBOARD_COPIED, {"entry_id": 1}))

        self.assertEqual(added, 1)
        self.assertEqual(deleted, 1)
        self.assertEqual(clipboard_copied, 1)

    def test_audit_logger_stub(self):
        logger = AuditLoggerStub(self.event_bus)
        self.assertIsNotNone(logger)
        try:
            self.event_bus.publish(Event(EventType.ENTRY_ADDED, {}))
            self.event_bus.publish(Event(EventType.USER_LOGGED_IN, "test"))
        except Exception as error:
            self.fail(f"AuditLoggerStub вызвал ошибку: {error}")

    def test_audit_logger_records_clipboard_events_with_details(self):
        database = FakeAuditDatabase()
        logger = AuditLogger(database, self.event_bus, key_provider=lambda: b"a" * 32)
        self.addCleanup(logger.close)

        copied_event = Event(
            EventType.CLIPBOARD_COPIED,
            {"entry_id": 7, "data_type": "password", "timeout_seconds": 30, "source_label": "GitHub"},
        )
        copied_event.timestamp = datetime(2026, 4, 7, 12, 0, 0)
        cleared_event = Event(
            EventType.CLIPBOARD_CLEARED,
            {"reason": "monitor_warning", "entry_id": 7, "data_type": "password", "observed_length": 21},
        )
        cleared_event.timestamp = datetime(2026, 4, 7, 12, 0, 1)

        self.event_bus.publish(copied_event)
        self.event_bus.publish(cleared_event)
        logger.flush()

        self.assertEqual(len(database.records), 3)
        self.assertEqual(database.records[1]["action"], "clipboard_copied")
        self.assertEqual(database.records[1]["entry_id"], 7)
        self.assertIn('"data_type": "password"', database.records[1]["details"])
        self.assertIn('"timeout_seconds": 30', database.records[1]["details"])
        self.assertEqual(database.records[2]["action"], "clipboard_cleared")
        self.assertEqual(database.records[2]["entry_id"], 7)
        self.assertIn('"reason": "monitor_warning"', database.records[2]["details"])
        self.assertIn('"observed_length": 21', database.records[2]["details"])

    def test_audit_logger_records_clipboard_error_without_secret_payload(self):
        database = FakeAuditDatabase()
        logger = AuditLogger(database, self.event_bus, key_provider=lambda: b"a" * 32)
        self.addCleanup(logger.close)

        error_event = Event(
            EventType.CLIPBOARD_ERROR,
            {"operation": "copy", "error_code": "adapter_write_failed", "entry_id": 7, "data_type": "password"},
        )
        self.event_bus.publish(error_event)
        logger.flush()

        self.assertEqual(database.records[-1]["action"], "clipboard_error")
        self.assertEqual(database.records[-1]["entry_id"], 7)
        self.assertIn('"error_code": "adapter_write_failed"', database.records[-1]["details"])
        self.assertNotIn("Secret!123", database.records[-1]["details"])

    def test_audit_logger_hashes_personal_data_fields(self):
        database = FakeAuditDatabase()
        logger = AuditLogger(database, self.event_bus, key_provider=lambda: b"a" * 32)
        self.addCleanup(logger.close)

        self.event_bus.publish(
            Event(
                EventType.USER_LOGIN_FAILED,
                {
                    "reason": "invalid_password",
                    "username": "user@example.com",
                    "failed_attempts": 3,
                },
            )
        )
        logger.flush()

        self.assertEqual(database.records[-1]["action"], "user_login_failed")
        self.assertIn('"failed_attempts": 3', database.records[-1]["details"])
        self.assertNotIn("user@example.com", database.records[-1]["details"])

    def test_audit_logger_records_future_integration_events(self):
        database = FakeAuditDatabase()
        logger = AuditLogger(database, self.event_bus, key_provider=lambda: b"a" * 32)
        self.addCleanup(logger.close)

        self.event_bus.publish(
            Event(
                EventType.IMPORT_OPERATION_COMPLETED,
                {
                    "format": "json",
                    "record_count": 12,
                    "source_file": "backup.json",
                },
            )
        )
        self.event_bus.publish(
            Event(
                EventType.PANIC_MODE_ACTIVATED,
                {
                    "reason": "manual",
                    "secret": "Sensitive",
                },
            )
        )
        self.event_bus.publish(
            Event(
                EventType.TOTP_VERIFICATION_PERFORMED,
                {
                    "account": "mail",
                    "result": "failed",
                },
            )
        )
        logger.flush()

        actions = [record["action"] for record in database.records]
        self.assertIn("import_operation_completed", actions)
        self.assertIn("panic_mode_activated", actions)
        self.assertIn("totp_verification_performed", actions)
        panic_record = next(record for record in database.records if record["action"] == "panic_mode_activated")
        self.assertEqual(panic_record["severity"], "CRITICAL")
        self.assertNotIn("Sensitive", panic_record["details"])

    def test_audit_logger_verifies_integrity_for_valid_chain(self):
        database = FakeAuditDatabase()
        logger = AuditLogger(database, self.event_bus, key_provider=lambda: b"a" * 32)
        self.addCleanup(logger.close)

        self.event_bus.publish(Event(EventType.SETTINGS_CHANGED, {"scope": "security"}))
        logger.flush()
        results = logger.verify_integrity()

        self.assertTrue(results["verified"])
        self.assertEqual(results["total_entries"], 2)
        self.assertEqual(results["valid_entries"], 2)

    def test_audit_log_signer_signs_and_verifies_with_separate_context_key(self):
        signer = AuditLogSigner(lambda: b"k" * 32)
        payload = b'{"event":"clipboard_copied"}'
        signature = signer.sign(payload)

        self.assertEqual(signer.algorithm, "ed25519")
        self.assertTrue(signer.verify(payload, signature, signer.public_key_hex))
        self.assertFalse(signer.verify(b"tampered", signature, signer.public_key_hex))

    def test_audit_log_signer_uses_distinct_forward_secure_keys_per_sequence(self):
        signer = AuditLogSigner(lambda: b"q" * 32)
        payload = b'{"event":"settings_changed"}'

        signature_one = signer.sign_for_sequence(payload, 1)
        signature_two = signer.sign_for_sequence(payload, 2)
        public_key_one = signer.public_key_for_sequence(1)
        public_key_two = signer.public_key_for_sequence(2)

        self.assertNotEqual(public_key_one, public_key_two)
        self.assertNotEqual(signature_one, signature_two)
        self.assertTrue(signer.verify(payload, signature_one, public_key_one))
        self.assertTrue(signer.verify(payload, signature_two, public_key_two))
        self.assertFalse(signer.verify(payload, signature_one, public_key_two))

    def test_audit_log_verifier_detects_hash_chain_tampering(self):
        class AuditRow:
            def __init__(self, sequence_number, entry_data, entry_hash, previous_hash, signature, public_key):
                self.sequence_number = sequence_number
                self.entry_data = entry_data
                self.entry_hash = entry_hash
                self.previous_hash = previous_hash
                self.signature = signature
                self.public_key = public_key

        signer = AuditLogSigner(lambda: b"z" * 32)
        payload1 = '{"event_type":"system_genesis","sequence_number":1}'
        payload2 = '{"event_type":"clipboard_copied","sequence_number":2}'
        hash1 = __import__("hashlib").sha256(payload1.encode("utf-8")).hexdigest()
        hash2 = __import__("hashlib").sha256(payload2.encode("utf-8")).hexdigest()
        rows = [
            AuditRow(1, payload1, hash1, "0" * 64, signer.sign(payload1.encode("utf-8")), signer.public_key_hex),
            AuditRow(2, payload2, hash2, "broken-chain", signer.sign(payload2.encode("utf-8")), signer.public_key_hex),
        ]

        class FakeVerifierDatabase:
            def get_audit_log_chain(self, start_sequence=0, limit=None):
                return rows

        results = AuditLogVerifier(FakeVerifierDatabase(), signer).verify()
        self.assertFalse(results["verified"])
        self.assertEqual(results["chain_breaks"][0]["sequence_number"], 2)


if __name__ == "__main__":
    unittest.main()