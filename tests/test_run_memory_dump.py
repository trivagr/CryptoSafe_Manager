import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
import uuid
from pathlib import Path

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from tests.test_clipboard import _contains_secret_in_process_memory, _derive_memory_dump_secret


class TestClipboardAdapter:
    def copy_to_clipboard(self, data: str) -> bool:
        return True

    def clear_clipboard(self) -> bool:
        return True

    def get_clipboard_content(self):
        return None


def wipe(buffer: bytearray):
    for index in range(len(buffer)):
        buffer[index] = 0


def read_seed() -> bytearray:
    seed = bytearray()
    while True:
        chunk = sys.stdin.buffer.read(1)
        if not chunk or chunk == b"\n":
            break
        if chunk != b"\r":
            seed.extend(chunk)
    return seed


def make_password(seed_bytes: bytearray) -> bytearray:
    alphabet = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
    state = 0xA5A5A5A5
    for value in seed_bytes:
        state = ((state << 5) ^ (state >> 2) ^ value) & 0xFFFFFFFF

    password = bytearray(b"TEST3-")
    for _index in range(32):
        state = (1664525 * state + 1013904223) & 0xFFFFFFFF
        password.append(alphabet[state % len(alphabet)])
    return password


def run_memory_dump_mode():
    import gc

    from src.core.clipboard import ClipboardService
    from src.core.events import EventBus
    from src.core.state_manager import StateManager
    from src.database.db import Database

    seed = read_seed()
    if not seed:
        raise SystemExit(2)
    password = make_password(seed)
    wipe(seed)

    with tempfile.TemporaryDirectory() as temp_dir:
        database = Database(str(Path(temp_dir) / "run-memory-dump.db"))
        try:
            state_manager = StateManager()
            state_manager.unlock()
            clipboard_service = ClipboardService(
                TestClipboardAdapter(),
                database=database,
                state_manager=state_manager,
                bus=EventBus(),
            )
            clipboard_service.configure(delivery_mode="memory_only")
            clipboard_service.copy_secret_bytes(
                password,
                data_type="password",
                source_label="Memory dump test",
                wipe_input=True,
            )
            wipe(password)
            gc.collect()
            sys.stdout.write(json.dumps({"pid": os.getpid(), "status": "ready", "scenario": "run-memory-dump"}) + "\n")
            sys.stdout.flush()
            time.sleep(10)
            clipboard_service.clear(reason="test_complete")
            gc.collect()
        finally:
            database.close()


class TestRunMemoryDump(unittest.TestCase):
    @pytest.mark.slow
    def test_run_process_memory_dump(self):
        run_path = Path(__file__).resolve().parents[1] / "run.py"
        if not run_path.exists():
            self.fail("Missing run.py")

        seed_bytes = f"run-memory-dump-{uuid.uuid4().hex}-{time.time_ns()}".encode("utf-8")
        expected_secret = _derive_memory_dump_secret(seed_bytes)
        env = os.environ.copy()
        env["CRYPTOSAFE_RUN_MEMORY_DUMP_TEST"] = "1"

        process = subprocess.Popen(
            [sys.executable, "-u", str(run_path)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
        )

        try:
            process.stdin.write(seed_bytes + b"\n")
            process.stdin.flush()
            process.stdin.close()

            ready_line = process.stdout.readline().decode("utf-8", errors="replace").strip()
            if not ready_line:
                stderr_output = process.stderr.read().decode("utf-8", errors="replace")
                self.fail(f"run.py did not start memory dump mode: {stderr_output}")

            ready = json.loads(ready_line)
            self.assertEqual(ready.get("status"), "ready")
            self.assertEqual(ready.get("scenario"), "run-memory-dump")
            self.assertFalse(
                _contains_secret_in_process_memory(int(ready["pid"]), expected_secret),
                "Password was found in run.py memory dump",
            )
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
            if process.stdout is not None:
                process.stdout.close()
            if process.stderr is not None:
                process.stderr.close()


if __name__ == "__main__":
    unittest.main()