import gc
import json
import os
import sys
import time

from .memory_guard import SecureBuffer


def derive_security_dump_secret(seed_bytes: bytes | bytearray) -> bytes:
    return bytes(derive_security_dump_secret_buffer(seed_bytes))


def derive_security_dump_secret_buffer(seed_bytes: bytes | bytearray) -> bytearray:
    alphabet = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
    state = 0xC0DEC0DE
    for value in seed_bytes:
        state = ((state << 7) ^ (state >> 3) ^ value) & 0xFFFFFFFF

    derived = bytearray(b"SPRINT7-")
    for _index in range(40):
        state = (1103515245 * state + 12345) & 0xFFFFFFFF
        derived.append(alphabet[state % len(alphabet)])
    return derived


def _wipe(buffer: bytearray) -> None:
    for index in range(len(buffer)):
        buffer[index] = 0


def _read_seed_from_stdin() -> bytearray:
    seed = bytearray()
    while True:
        chunk = sys.stdin.buffer.read(1)
        if not chunk or chunk == b"\n":
            break
        if chunk != b"\r":
            seed.extend(chunk)
    return seed


def run_security_memory_dump_mode() -> None:
    seed = _read_seed_from_stdin()
    if not seed:
        raise SystemExit(2)

    secret = derive_security_dump_secret_buffer(seed)
    _wipe(seed)

    secure_buffer = SecureBuffer(secret)
    secure_buffer.close()
    _wipe(secret)
    del secure_buffer
    del secret
    gc.collect()

    sys.stdout.write(json.dumps({"pid": os.getpid(), "status": "ready", "scenario": "sprint7-security-memory-dump"}) + "\n")
    sys.stdout.flush()
    time.sleep(10)