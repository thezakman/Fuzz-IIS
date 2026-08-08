"""Result data model."""
from __future__ import annotations

from dataclasses import asdict, dataclass


@dataclass
class Finding:
    target: str
    method: str = "GET"
    status_code: int | None = None
    content_length: int | None = None
    content_type: str | None = None
    server: str | None = None
    elapsed_ms: float | None = None
    location: str | None = None
    sample: str | None = None
    header_name: str | None = None
    header_value: str | None = None
    error: str | None = None
    matched: bool = False

    def as_dict(self) -> dict:
        return asdict(self)
