import ctypes
import secrets
import platform
from dataclasses import dataclass, field
from typing import Any


@dataclass
class SecureMemoryStatus:
    platform: str
    locked: bool
    degraded: bool
    reason: str = ""


class MemoryGuard:
    def __init__(self):
        self.system = platform.system()
        self._libc = None
        self._kernel32 = None
        if self.system == "Windows":
            try:
                self._kernel32 = ctypes.windll.kernel32
            except Exception:
                self._kernel32 = None
        elif self.system in {"Linux", "Darwin"}:
            try:
                self._libc = ctypes.CDLL(None)
            except Exception:
                self._libc = None

    def allocate(self, size: int) -> tuple[Any, SecureMemoryStatus]:
        selected_size = max(1, int(size))
        buffer = (ctypes.c_ubyte * selected_size)()
        status = self.lock(buffer, selected_size)
        return buffer, status

    def lock(self, buffer: Any, size: int) -> SecureMemoryStatus:
        selected_size = max(1, int(size))
        if self.system == "Windows" and self._kernel32 is not None:
            try:
                locked = bool(self._kernel32.VirtualLock(ctypes.byref(buffer), selected_size))
                return SecureMemoryStatus(self.system, locked=locked, degraded=not locked, reason="" if locked else "VirtualLock failed")
            except Exception as exc:
                return SecureMemoryStatus(self.system, locked=False, degraded=True, reason=str(exc))
        if self.system in {"Linux", "Darwin"} and self._libc is not None:
            try:
                locked = self._libc.mlock(ctypes.byref(buffer), selected_size) == 0
                return SecureMemoryStatus(self.system, locked=locked, degraded=not locked, reason="" if locked else "mlock failed")
            except Exception as exc:
                return SecureMemoryStatus(self.system, locked=False, degraded=True, reason=str(exc))
        return SecureMemoryStatus(self.system, locked=False, degraded=True, reason="memory locking unavailable")

    def unlock(self, buffer: Any, size: int) -> SecureMemoryStatus:
        selected_size = max(1, int(size))
        if self.system == "Windows" and self._kernel32 is not None:
            try:
                unlocked = bool(self._kernel32.VirtualUnlock(ctypes.byref(buffer), selected_size))
                return SecureMemoryStatus(self.system, locked=False, degraded=not unlocked, reason="" if unlocked else "VirtualUnlock failed")
            except Exception as exc:
                return SecureMemoryStatus(self.system, locked=False, degraded=True, reason=str(exc))
        if self.system in {"Linux", "Darwin"} and self._libc is not None:
            try:
                unlocked = self._libc.munlock(ctypes.byref(buffer), selected_size) == 0
                return SecureMemoryStatus(self.system, locked=False, degraded=not unlocked, reason="" if unlocked else "munlock failed")
            except Exception as exc:
                return SecureMemoryStatus(self.system, locked=False, degraded=True, reason=str(exc))
        return SecureMemoryStatus(self.system, locked=False, degraded=True, reason="memory unlocking unavailable")

    def secure_zero(self, buffer: Any, size: int, *, passes: int = 1) -> None:
        selected_size = max(0, int(size))
        if selected_size == 0:
            return
        selected_passes = max(1, int(passes))
        for _ in range(selected_passes):
            ctypes.memset(ctypes.byref(buffer), 0, selected_size)

    def wipe_bytearray(self, buffer: bytearray | memoryview, *, passes: int = 1) -> None:
        view = memoryview(buffer)
        selected_passes = max(1, int(passes))
        for _ in range(selected_passes):
            for index in range(len(view)):
                view[index] = 0

    def copy_into(self, buffer: Any, data: bytes | bytearray | memoryview) -> int:
        if isinstance(data, bytearray):
            size = min(len(data), ctypes.sizeof(buffer))
            if size:
                source = (ctypes.c_ubyte * len(data)).from_buffer(data)
                ctypes.memmove(ctypes.byref(buffer), ctypes.byref(source), size)
            return size
        if isinstance(data, memoryview) and not data.readonly and data.contiguous:
            size = min(len(data), ctypes.sizeof(buffer))
            if size:
                source = (ctypes.c_ubyte * len(data)).from_buffer(data)
                ctypes.memmove(ctypes.byref(buffer), ctypes.byref(source), size)
            return size
        payload = bytes(data)
        size = min(len(payload), ctypes.sizeof(buffer))
        if size:
            ctypes.memmove(ctypes.byref(buffer), payload, size)
        return size

    def managed_overhead_ratio(self, requested_size: int) -> float:
        selected_size = max(1, int(requested_size))
        buffer, _status = self.allocate(selected_size)
        try:
            allocated_size = ctypes.sizeof(buffer)
            return max(0.0, (allocated_size - selected_size) / selected_size)
        finally:
            self.secure_zero(buffer, selected_size)
            self.unlock(buffer, selected_size)


@dataclass
class StackFrameGuard:
    secrets_to_wipe: list[bytearray] = field(default_factory=list)
    canary: bytes = field(default_factory=lambda: secrets.token_bytes(16))
    _volatile_sink: int = 0

    def protect(self, buffer: bytearray) -> bytearray:
        self.secrets_to_wipe.append(buffer)
        self._volatile_sink ^= len(buffer)
        return buffer

    def verify_canary(self) -> bool:
        return len(self.canary) == 16 and any(self.canary)

    def wipe(self) -> None:
        for buffer in self.secrets_to_wipe:
            view = memoryview(buffer)
            for index in range(len(view)):
                view[index] = 0
            self._volatile_sink ^= len(view)
        self.secrets_to_wipe.clear()

    def __enter__(self):
        if not self.verify_canary():
            raise RuntimeError("Stack frame canary check failed")
        return self

    def __exit__(self, _exc_type, _exc, _tb):
        try:
            if not self.verify_canary():
                raise RuntimeError("Stack frame canary check failed")
        finally:
            self.wipe()


class SecureBuffer:
    def __init__(self, data: bytes | bytearray | memoryview, guard: MemoryGuard | None = None):
        self.guard = guard or MemoryGuard()
        self.size = max(1, len(data))
        self.buffer, self.status = self.guard.allocate(self.size)
        self.guard.copy_into(self.buffer, data)
        if isinstance(data, bytearray):
            for index in range(len(data)):
                data[index] = 0

    def read(self) -> bytes:
        return bytes(bytearray(self.buffer)[: self.size])

    def wipe(self) -> None:
        if getattr(self, "buffer", None) is not None:
            self.guard.secure_zero(self.buffer, self.size)

    def close(self) -> None:
        if getattr(self, "buffer", None) is None:
            return
        self.wipe()
        self.guard.unlock(self.buffer, self.size)
        self.buffer = None

    def __enter__(self):
        return self

    def __exit__(self, _exc_type, _exc, _tb):
        self.close()

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass