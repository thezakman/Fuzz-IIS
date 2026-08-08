"""Small, dependency-free helpers shared across the package."""
from __future__ import annotations

import random
import string
from urllib.parse import urlparse

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) "
    "Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:45.0) Gecko/20100101 Firefox/45.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_2) AppleWebKit/602.3.12 (KHTML, like Gecko) "
    "Version/10.0.2 Safari/602.3.12",
    "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
]


def random_user_agent(rng: random.Random | None = None) -> str:
    r = rng or random
    return r.choice(USER_AGENTS)


def random_string(length: int, rng: random.Random | None = None) -> str:
    r = rng or random
    alphabet = string.ascii_letters + string.digits
    return "".join(r.choice(alphabet) for _ in range(max(1, length)))


def base_url(url: str) -> str:
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"


def path_parts(url: str) -> list[str]:
    p = urlparse(url)
    return [part for part in p.path.strip("/").split("/") if part != ""] or [""]


def parse_methods(raw: str) -> list[str]:
    return [m.strip().upper() for m in raw.split(",") if m.strip()]


def parse_header_line(line: str) -> tuple[str, str] | None:
    line = line.strip()
    if not line or line.startswith("#") or ":" not in line:
        return None
    name, _, value = line.partition(":")
    return name.strip(), value.strip()


def load_headers_file(path: str) -> dict:
    headers = {}
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            parsed = parse_header_line(line)
            if parsed:
                headers[parsed[0]] = parsed[1]
    return headers


def load_lines_file(path: str) -> list[str]:
    with open(path, "r", encoding="utf-8") as fh:
        return [ln.strip() for ln in fh if ln.strip() and not ln.strip().startswith("#")]


def parse_cookie_string(raw: str) -> dict:
    cookies = {}
    for part in raw.split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        k, _, v = part.partition("=")
        cookies[k.strip()] = v.strip()
    return cookies
