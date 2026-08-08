"""Thread-safe, smooth (token-bucket-ish) rate limiter.

Unlike a plain ``time.sleep(delay)`` inserted after each completed request on
the main thread (the old behaviour), this schedules an absolute "not before"
timestamp per call so a global requests/second cap holds even when many
worker threads are hammering ``wait()`` concurrently.
"""
from __future__ import annotations

import threading
import time


class RateLimiter:
    def __init__(self, rate_per_sec: float = 0.0):
        self.interval = 1.0 / rate_per_sec if rate_per_sec and rate_per_sec > 0 else 0.0
        self._lock = threading.Lock()
        self._next_slot = time.monotonic()

    def wait(self) -> None:
        if not self.interval:
            return
        with self._lock:
            now = time.monotonic()
            if self._next_slot < now:
                self._next_slot = now
            slot = self._next_slot
            self._next_slot += self.interval
        delay = slot - time.monotonic()
        if delay > 0:
            time.sleep(delay)
