"""Optional TOML configuration file support.

Precedence (lowest to highest): built-in argparse defaults -> config file ->
actual CLI flags. This lets a user pin e.g. their preferred thread count,
timeout or proxy once instead of retyping it on every invocation.
"""
from __future__ import annotations

import os
import sys

try:
    import tomllib  # Python >= 3.11
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib  # type: ignore

DEFAULT_CONFIG_PATH = os.path.expanduser("~/.config/iisfuzz/config.toml")

# Maps [section] keys in the TOML file to argparse `dest` names.
_FLAT_KEYS = {
    "threads", "rate", "delay", "timeout", "retries", "backoff", "method",
    "proxy", "insecure", "user_agent", "random_agent", "output", "format",
    "verbose", "quiet", "no_color", "no_banner", "log", "resume", "seed",
    "match_status", "filter_status", "match_length", "filter_length",
    "match_regex", "filter_regex", "content_sample", "sample_length",
    "fuzz_mode", "vary", "max_x_length", "bruteforce", "min_word_length",
    "dir_traversal", "encoding_tricks", "index_allocation", "xss", "static",
    "shuffle", "max_payloads", "bypass_headers", "test_headers",
    "no_default_cookies", "no_baseline",
}


def load_config(path: str | None) -> dict:
    candidate = path or (DEFAULT_CONFIG_PATH if os.path.exists(DEFAULT_CONFIG_PATH) else None)
    if not candidate:
        return {}
    if not os.path.exists(candidate):
        print(f"[!] Config file not found: {candidate}", file=sys.stderr)
        return {}
    with open(candidate, "rb") as fh:
        data = tomllib.load(fh)

    flat: dict = {}
    for section, values in data.items():
        if isinstance(values, dict):
            flat.update(values)
        else:
            flat[section] = values

    return {k: v for k, v in flat.items() if k in _FLAT_KEYS}
