"""Checkpoint support so a long fuzzing run can be interrupted and resumed.

The checkpoint file is a flat text file of opaque task keys (one per line),
appended to as each task completes. On restart with the same ``--resume``
path, already-completed keys are skipped.
"""
from __future__ import annotations

import hashlib
import os
import threading


def task_key(*parts: str) -> str:
    joined = "\x1f".join(parts)
    return hashlib.sha1(joined.encode("utf-8", "surrogateescape")).hexdigest()


class ResumeState:
    def __init__(self, path: str | None):
        self.path = path
        self._done: set[str] = set()
        self._lock = threading.Lock()
        self._fh = None
        if self.path and os.path.exists(self.path):
            with open(self.path, "r", encoding="utf-8") as fh:
                self._done = {line.strip() for line in fh if line.strip()}
        if self.path:
            self._fh = open(self.path, "a", encoding="utf-8", buffering=1)

    def is_done(self, key: str) -> bool:
        return key in self._done

    def mark_done(self, key: str) -> None:
        if not self.path:
            return
        with self._lock:
            if key in self._done:
                return
            self._done.add(key)
            self._fh.write(key + "\n")

    @property
    def completed_count(self) -> int:
        return len(self._done)

    def close(self) -> None:
        if self._fh:
            self._fh.close()
