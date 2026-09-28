import os
import sqlite3
import sys
import tempfile
import time
import tracemalloc
import unittest
import json
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.core.audit import AuditLogger, AuditLogSigner, AuditLogVerifier, export_logs_to_cef, export_logs_to_json, import_logs_from_json
from src.core.crypto.authentication import AuthenticationService
from src.core.crypto.key_derivation import KeyDerivation
from src.core.crypto.key_storage import KeyStorage
from src.core.crypto.password_validator import PasswordValidator
from src.core.events import Event, EventBus, EventType
from src.core.state_manager import StateManager
from src.database.db import Database


class TestAuditLogging(unittest.TestCase):
    def setUp(self):
        self.temp_file = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.temp_file.close()
        self.database = Database(self.temp_file.name)
        self.event_bus = EventBus()
        self.logger = AuditLogger(self.database, self.event_bus, key_provider=lambda: b"a" * 32)
        self.verifier = AuditLogVerifier(self.database, self.logger.signer)

    def tearDown(self):
        self.logger.close()
        self.database.close()
        try:
            os.unlink(self.temp_file.name)
        except OSError:
            pass

    def _generate_logs(self, total: int, *, flush: bool = True):
        for index in range(total):
            self.logger.log_event(
                event_type="settings_changed",
                severity="WARN" if index % 10 == 0 else "INFO",
                source="configuration",
                details={
                    "scope": "security",
                    "changed_keys": [f"setting_{index % 5}"],
                    "record": index,
                },
                user_id="local-user",
            )
        if flush:
            self.logger.flush()

    def test_detects_tampered_audit_entry(self):
        #сначала создаём длинную нормальную цепочку аудит-записей
        self._generate_logs(1000)

        with self.database._get_connection() as conn:
            #в обычной работе апдейт запрещён триггером, поэтому для теста
            #временно убираем защиту и портим одну запись в БД
            conn.execute("DROP TRIGGER IF EXISTS trg_audit_log_no_update")
            conn.execute(
                "UPDATE audit_log SET entry_data = ? WHERE sequence_number = ?",
                ('{"tampered":true}', 501),
            )

        #верифаер должен заметить, что подпись/хэш у записи больше не сходятся
        results = self.verifier.verify()

        self.assertFalse(results["verified"])
        self.assertTrue(any(item["sequence_number"] == 501 for item in results["invalid_entries"]))

    @pytest.mark.slow
    def test_audit_performance_10000_events(self):
        #проверяем, что аудит сабсистем выдерживает большой объём событий
        started_at = time.perf_counter()
        self._generate_logs(10000, flush=False)
        enqueue_elapsed = time.perf_counter() - started_at
        average_logging_time = enqueue_elapsed / 10000

        flush_started_at = time.perf_counter()
        self.logger.flush()
        flush_elapsed = time.perf_counter() - flush_started_at

        verification_started_at = time.perf_counter()
        verification_result = self.verifier.verify(start_sequence=9001)
        verification_elapsed = time.perf_counter() - verification_started_at

        query_started_at = time.perf_counter()
        filtered_logs = self.database.query_audit_logs(
            search_text="security",
            event_type="settings_changed",
            limit=100,
            offset=0,
        )
        query_elapsed = time.perf_counter() - query_started_at

        tracemalloc.start()
        _ = self.database.query_audit_logs(limit=10000, offset=0)
        _current, peak_memory = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        self.assertTrue(verification_result["verified"])
        self.assertEqual(len(filtered_logs), 100)
        self.assertGreaterEqual(self.database.count_audit_logs(), 10001)
        self.assertLess(average_logging_time, 0.01)
        self.assertGreater(flush_elapsed, 0.0)
        self.assertLess(verification_elapsed, 1.0)
        self.assertLess(query_elapsed, 0.5)
        self.assertLess(peak_memory, 50 * 1024 * 1024)

    def test_signed_json_export_import(self):
        self._generate_logs(25)
        original_logs = self.database.get_audit_log_chain()
        exported_json = export_logs_to_json(original_logs, public_key=self.logger.signer.public_key_hex)

        #подписанный джсон проверяется отдельным верифаером, а не тем же логгер-объектом
        independent_verifier = AuditLogVerifier(self.database, AuditLogSigner(lambda: b"b" * 32))
        exported_verification = independent_verifier.verify_exported_json(exported_json)
        self.assertTrue(exported_verification["verified"])

        #после обратного импорта цепочка также должна остаться валидной
        imported_entries = import_logs_from_json(exported_json)
        imported_temp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        imported_temp.close()
        imported_database = Database(imported_temp.name)
        try:
            imported_database.import_audit_logs(imported_entries)
            imported_verifier = AuditLogVerifier(imported_database, self.logger.signer)
            imported_results = imported_verifier.verify()
            self.assertTrue(imported_results["verified"])
            self.assertEqual(imported_results["total_entries"], len(imported_entries))
        finally:
            imported_database.close()
            try:
                os.unlink(imported_temp.name)
            except OSError:
                pass

    def test_cef_export_contains_standard_header_and_extensions(self):
        self._generate_logs(2)
        logs = self.database.get_audit_log_chain()

        cef_payload = export_logs_to_cef(logs)
        first_line = cef_payload.splitlines()[0]

        self.assertTrue(first_line.startswith("CEF:0|CryptoSafe|Manager|5|"))
        self.assertIn("rt=", first_line)
        self.assertIn("suser=", first_line)
        self.assertIn("cn1Label=sequence_number", first_line)

    def test_database_error_returns_recovery_options(self):
        self._generate_logs(5)

        #имитируем ошибку чтения аудит тэйбл верифаер не должен падать наружу
        with patch.object(self.database, "get_audit_log_chain", side_effect=sqlite3.DatabaseError("corrupted")):
            results = self.verifier.verify()

        self.assertFalse(results["verified"])
        self.assertEqual(results["invalid_entries"][0]["reason"], "database_error")
        self.assertIn("restore_from_backup", results["recovery_options"])

    def test_corrupted_database_file_returns_recovery_options(self):
        #это уже не мокк, создаём настоящий файл, который скулайт не может прочитать
        corrupted_temp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        corrupted_temp.write(b"not a sqlite database")
        corrupted_temp.close()

        class CorruptedDatabase:
            def get_audit_log_chain(self, start_sequence=0, limit=None):
                connection = sqlite3.connect(corrupted_temp.name)
                try:
                    connection.execute("SELECT * FROM audit_log").fetchall()
                finally:
                    connection.close()

        try:
            verifier = AuditLogVerifier(CorruptedDatabase(), self.logger.signer)
            results = verifier.verify()
        finally:
            try:
                os.unlink(corrupted_temp.name)
            except OSError:
                pass

        #вместо краша пользователь получает понятный статус и варианты восстановления
        self.assertFalse(results["verified"])
        self.assertEqual(results["invalid_entries"][0]["reason"], "database_error")
        self.assertIn("restore_from_backup", results["recovery_options"])
        self.assertIn("export_verification_report", results["recovery_options"])
        self.assertIn("rebuild_audit_log", results["recovery_options"])

    def test_sql_injection_search_does_not_change_audit_log(self):
        self._generate_logs(10)
        malicious_search = "'; DROP TABLE audit_log; --"

        #cтрока поиска должна уйти в скулайт как параметр, а не как часть запроса
        results = self.database.query_audit_logs(search_text=malicious_search, limit=10, offset=0)
        remaining_count = self.database.count_audit_logs()

        self.assertEqual(results, [])
        self.assertEqual(remaining_count, 11)

    def test_audit_log_entry_data_is_encrypted_at_rest_and_decrypted_on_read(self):
        self._generate_logs(1)

        with self.database._get_connection() as conn:
            raw_row = conn.execute(
                "SELECT entry_data FROM audit_log WHERE sequence_number = 2"
            ).fetchone()

        raw_entry_data = raw_row["entry_data"]
        self.assertNotIn('"event_type": "settings_changed"', raw_entry_data)
        self.assertTrue(json.loads(raw_entry_data)["encrypted"])

        log = self.database.get_audit_log_by_sequence(2)
        self.assertIn('"event_type": "settings_changed"', log.entry_data)

    def test_audit_entry_payloads_are_reencrypted_when_master_key_rotates(self):
        active_key = {"value": b"a" * 32}
        self.logger.close()
        self.logger = AuditLogger(self.database, self.event_bus, key_provider=lambda: active_key["value"])
        self.verifier = AuditLogVerifier(self.database, self.logger.signer)

        self.logger.log_event(
            event_type="settings_changed",
            severity="INFO",
            source="configuration",
            details={"scope": "security"},
            user_id="local-user",
            force_sync=True,
        )
        self.assertTrue(self.verifier.verify()["verified"])

        old_key = active_key["value"]
        new_key = b"b" * 32
        active_key["value"] = new_key
        self.assertFalse(self.verifier.verify()["verified"])

        rotated = self.logger.reencrypt_entry_payloads(old_key, new_key)

        self.assertGreaterEqual(rotated, 1)
        self.assertTrue(self.verifier.verify()["verified"])

    def test_audit_integrity_survives_authentication_master_password_change(self):
        self.logger.close()
        self.database.close()
        try:
            os.unlink(self.temp_file.name)
        except OSError:
            pass

        self.temp_file = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.temp_file.close()
        self.database = Database(self.temp_file.name)
        key_storage = KeyStorage(self.database)
        auth_service = AuthenticationService(
            key_storage,
            KeyDerivation({}),
            PasswordValidator(),
            StateManager(),
        )
        auth_service.register_master_password("OldStrong!7xQ")
        self.logger = AuditLogger(self.database, self.event_bus, key_provider=auth_service.get_active_key)
        self.verifier = AuditLogVerifier(self.database, self.logger.signer)
        self.logger.log_event(
            event_type="settings_changed",
            severity="INFO",
            source="configuration",
            details={"scope": "security"},
            user_id="local-user",
            force_sync=True,
        )
        self.assertTrue(self.verifier.verify()["verified"])

        auth_service.change_master_password(
            "OldStrong!7xQ",
            "NewStrong!8zR",
            rotate_entries_callback=lambda old_key, new_key: self.logger.reencrypt_entry_payloads(old_key, new_key),
        )

        self.assertTrue(self.verifier.verify()["verified"])

    def test_audit_entry_includes_utc_reliable_time_source_metadata(self):
        self._generate_logs(1)

        log = self.database.get_audit_log_by_sequence(2)
        payload = json.loads(log.entry_data)

        self.assertTrue(payload["timestamp"].endswith("Z"))
        self.assertEqual(payload["time_source"]["timezone"], "UTC")
        self.assertTrue(payload["time_source"]["synchronized"])
        self.assertEqual(payload["time_source"]["reliable_source"], "operating_system_clock")

    def test_append_only_blocks_changes_and_logs_them(self):
        self._generate_logs(3)

        #прямой апдейт и попытка отключить защиту блокируются
        with self.assertRaises(sqlite3.DatabaseError):
            self.database.try_update_audit_log_entry(2, '{"tampered":true}')
        with self.assertRaises(PermissionError):
            self.database.try_disable_audit_guards()
        self.logger.flush()

        #сами попытки вмешательства тоже попадают в отдельный секурити лог
        logs = self.database.get_audit_log_chain()
        self.assertEqual(logs[-2].event_type, "audit_log_protection_triggered")
        self.assertIn('"operation": "update"', logs[-2].details)
        self.assertEqual(logs[-1].event_type, "audit_log_protection_triggered")
        self.assertIn('"operation": "disable_protection"', logs[-1].details)
        security_events = self.database.get_audit_security_events(limit=5)
        self.assertEqual(security_events[0]["event_type"], "audit_log_protection_triggered")
        self.assertEqual(security_events[1]["event_type"], "audit_log_protection_triggered")

    def test_rotation_policy_archives_ranges_without_breaking_active_chain(self):
        self.logger.close()
        self.database.set_audit_retention_policy(max_entries=5, max_age_days=3650, enabled=True)
        self.logger = AuditLogger(
            self.database,
            self.event_bus,
            key_provider=lambda: b"a" * 32,
            config={"async_logging_enabled": False},
        )
        self.verifier = AuditLogVerifier(self.database, self.logger.signer)

        self._generate_logs(7)

        archives = self.database.get_audit_archives()
        archived_count = sum(int(item["entry_count"]) for item in archives)
        verification_result = self.verifier.verify()

        self.assertGreaterEqual(archived_count, 3)
        self.assertTrue(verification_result["verified"])

    def test_async_logging_flushes_non_critical_events_and_keeps_critical_sync(self):
        record_id = self.logger.log_event(
            event_type="settings_changed",
            severity="INFO",
            source="configuration",
            details={"scope": "security"},
            user_id="local-user",
        )
        self.assertEqual(record_id, 0)

        self.logger.flush()
        self.assertEqual(self.database.count_audit_logs(), 2)

        critical_record_id = self.logger.log_event(
            event_type="audit_verification_failed",
            severity="ERROR",
            source="audit",
            details={"reason": "chain_break"},
            user_id="system",
        )
        self.assertGreater(critical_record_id, 0)

    def test_audit_logger_skips_events_when_active_key_is_locked(self):
        locked_logger = AuditLogger(self.database, self.event_bus, key_provider=lambda: None)
        self.addCleanup(locked_logger.close)

        record_id = locked_logger.log_event(
            event_type="key_exchange_created",
            severity="INFO",
            source="key_exchange",
            details={"identifier": "alice@example.test"},
            user_id="local-user",
            force_sync=True,
        )

        self.assertEqual(record_id, 0)

    def test_integration_hook_receives_signed_audit_payload_without_breaking_logging(self):
        received_payloads = []
        self.logger.register_integration_hook(
            "siem",
            lambda payload: received_payloads.append(payload),
            event_types=["panic_mode_activated"],
        )

        record_id = self.logger.log_event(
            event_type="panic_mode_activated",
            severity="CRITICAL",
            source="panic_mode",
            details={"reason": "user_request", "secret": "Sensitive"},
            user_id="local-user",
            force_sync=True,
        )

        self.assertGreater(record_id, 0)
        self.assertEqual(len(received_payloads), 1)
        self.assertEqual(received_payloads[0]["event_type"], "panic_mode_activated")
        self.assertEqual(received_payloads[0]["details"]["secret"], "[REDACTED]")
        self.assertIn("entry_hash", received_payloads[0])

    def test_integration_hook_failure_is_recorded_in_secure_log(self):
        def failing_hook(_payload):
            raise RuntimeError("hook unavailable")

        self.logger.register_integration_hook("broken-hook", failing_hook)

        self.logger.log_event(
            event_type="totp_code_generated",
            severity="INFO",
            source="totp",
            details={"account": "example"},
            user_id="local-user",
            force_sync=True,
        )

        security_events = self.database.get_audit_security_events(limit=1)
        self.assertEqual(security_events[0]["event_type"], "audit_integration_hook_failed")
        self.assertIn("broken-hook", security_events[0]["details"])

    def test_import_export_share_events_have_sources(self):
        self.event_bus.publish(Event(EventType.EXPORT_OPERATION_COMPLETED, {"format": "encrypted_json", "entry_count": 3}))
        self.event_bus.publish(Event(EventType.IMPORT_OPERATION_COMPLETED, {"format": "csv", "created": 2}))
        self.event_bus.publish(Event(EventType.SHARE_CREATED, {"share_id": "share-1", "entry_id": 7}))
        self.event_bus.publish(Event(EventType.KEY_EXCHANGE_IMPORTED, {"identifier": "alice@example.test"}))
        self.logger.flush()

        logs = self.database.get_audit_log_chain()
        by_event = {log.event_type: log for log in logs}

        self.assertEqual(by_event["export_operation_completed"].source, "data_export")
        self.assertEqual(by_event["import_operation_completed"].source, "data_import")
        self.assertEqual(by_event["share_created"].source, "secure_sharing")
        self.assertEqual(by_event["key_exchange_imported"].source, "key_exchange")


if __name__ == "__main__":
    unittest.main()