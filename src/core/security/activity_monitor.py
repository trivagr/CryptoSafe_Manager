import threading
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Callable


@dataclass
class ActivityMonitorConfig:
    timeout_seconds: int = 300
    check_interval_seconds: float = 1.0
    sensitivity: str = "medium"
    device_profile: str = "desktop"

    def __post_init__(self):
        self.timeout_seconds = min(max(60, int(self.timeout_seconds)), 8 * 60 * 60)
        self.check_interval_seconds = max(0.1, float(self.check_interval_seconds))
        if self.sensitivity not in {"low", "medium", "high"}:
            self.sensitivity = "medium"
        if self.device_profile not in {"desktop", "laptop"}:
            self.device_profile = "desktop"


class ActivityMonitor:
    def __init__(
        self,
        lock_callback: Callable[[], None],
        config: ActivityMonitorConfig | None = None,
        *,
        clock: Callable[[], datetime] | None = None,
    ):
        self.lock_callback = lock_callback
        self.config = config or ActivityMonitorConfig()
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.last_activity = self.clock()
        self.monitoring = False
        self._thread: threading.Thread | None = None
        self._lock = threading.RLock()
        self._lock_count = 0

    def record_activity(self, source: str = "user") -> None:
        if not self._accept_activity(source):
            return
        with self._lock:
            self.last_activity = self.clock()

    def get_idle_seconds(self) -> float:
        with self._lock:
            return max(0.0, (self.clock() - self.last_activity).total_seconds())

    def should_lock(self) -> bool:
        return self.get_idle_seconds() >= self.config.timeout_seconds

    def tick(self) -> bool:
        if not self.should_lock():
            return False
        with self._lock:
            self._lock_count += 1
            self.last_activity = self.clock()
        self.lock_callback()
        return True

    def start(self) -> None:
        with self._lock:
            if self.monitoring:
                return
            self.monitoring = True
            self._thread = threading.Thread(target=self._run, name="security-activity-monitor", daemon=True)
            self._thread.start()

    def stop(self) -> None:
        with self._lock:
            self.monitoring = False
            thread = self._thread
        if thread is not None:
            thread.join(timeout=2.0)

    @property
    def lock_count(self) -> int:
        with self._lock:
            return self._lock_count

    def simulate_elapsed(self, seconds: int | float) -> None:
        with self._lock:
            self.last_activity = self.last_activity - timedelta(seconds=float(seconds))

    def _run(self) -> None:
        while True:
            with self._lock:
                if not self.monitoring:
                    return
            self.tick()
            time.sleep(self.config.check_interval_seconds)

    def _accept_activity(self, source: str) -> bool:
        if self.config.sensitivity == "high":
            return True
        if self.config.sensitivity == "medium":
            return source != "background"
        return source in {"keyboard", "mouse", "focus"}