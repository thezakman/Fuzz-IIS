"""Compose the final payload list from every enabled generator."""
from __future__ import annotations

import itertools
import random
from dataclasses import dataclass, field
from urllib.parse import urljoin

from ..utils import base_url as get_base_url, path_parts as get_path_parts
from .session_patterns import BASE_PATTERNS, iter_random_patterns
from .traversal import TRAVERSAL_PAYLOADS
from .index_allocation import INDEX_ALLOCATION_SUFFIXES
from .encoding_tricks import build_encoding_trick_paths
from .xss import XSS_PATTERNS
from .bruteforce import generate_word_mutations
from .static_aspnet import build_static_payloads


@dataclass
class FuzzOptions:
    fuzz_mode: str = "both"  # single | double | both
    patterns: list[str] = field(default_factory=lambda: list(BASE_PATTERNS))
    vary: int = 0
    max_x_length: int = 6
    bruteforce: bool = False
    min_word_length: int = 4
    dir_traversal: bool = False
    encoding_tricks: bool = False
    index_allocation: bool = False
    xss: bool = False
    static: bool = True
    shuffle: bool = False
    max_payloads: int | None = None
    seed: int | None = None


def _active_patterns(opts: FuzzOptions) -> list[str]:
    patterns = list(opts.patterns)
    if opts.vary > 0:
        rng = random.Random(opts.seed) if opts.seed is not None else random.Random()
        patterns.extend(iter_random_patterns(opts.vary, opts.max_x_length, rng))
    return patterns


def _session_id_payloads(url: str, opts: FuzzOptions) -> set[str]:
    parsed_base = get_base_url(url)
    parts = get_path_parts(url)
    patterns = _active_patterns(opts)
    out: set[str] = set()

    if opts.fuzz_mode in ("single", "both"):
        for i in range(len(parts) + 1):
            for pattern in patterns:
                new_parts = parts[:i] + [pattern] + parts[i:]
                out.add(urljoin(parsed_base, "/".join(new_parts)))

    if opts.fuzz_mode in ("double", "both"):
        for i in range(len(parts) + 1):
            for j in range(i, len(parts) + 1):
                for p1, p2 in itertools.product(patterns, repeat=2):
                    new_parts = parts[:i] + [p1] + parts[i:j] + [p2] + parts[j:]
                    out.add(urljoin(parsed_base, "/".join(new_parts)))

    return out


def _bruteforce_payloads(url: str, opts: FuzzOptions) -> set[str]:
    parsed_base = get_base_url(url)
    parts = get_path_parts(url)
    patterns = _active_patterns(opts)
    out: set[str] = set()

    for i, part in enumerate(parts):
        if len(part) <= opts.min_word_length:
            continue
        for mutation in generate_word_mutations(part, patterns):
            new_parts = parts.copy()
            new_parts[i] = mutation
            out.add(urljoin(parsed_base, "/".join(new_parts)))

    for i in range(len(parts) + 1):
        for pattern in patterns:
            new_parts = parts[:i] + [pattern] + parts[i:]
            out.add(urljoin(parsed_base, "/".join(new_parts)))

    return out


def _traversal_payloads(url: str) -> set[str]:
    parsed_base = get_base_url(url)
    parts = get_path_parts(url)
    path = "/".join(parts)
    return {urljoin(parsed_base, f"{path}/{p}") for p in TRAVERSAL_PAYLOADS}


def _index_allocation_payloads(url: str) -> set[str]:
    parsed_base = get_base_url(url)
    parts = get_path_parts(url)
    out: set[str] = set()
    for i in range(len(parts)):
        for suffix in INDEX_ALLOCATION_SUFFIXES:
            new_parts = parts.copy()
            new_parts[i] = new_parts[i] + suffix
            out.add(urljoin(parsed_base, "/".join(new_parts)))
    return out


def _encoding_trick_payloads(url: str) -> set[str]:
    parsed_base = get_base_url(url)
    path = "/".join(get_path_parts(url))
    return {urljoin(parsed_base, p) for p in build_encoding_trick_paths(path)}


def _xss_payloads(url: str) -> set[str]:
    parsed_base = get_base_url(url)
    path = "/".join(get_path_parts(url))
    out: set[str] = set()
    for suffix in XSS_PATTERNS:
        out.add(f"{parsed_base}/{path}{suffix}")
        out.add(f"{parsed_base}/(S(xss))/{path}{suffix}")
        out.add(f"{parsed_base}/{path}/(S(xss)){suffix}")
    return out


def build_payloads(url: str, opts: FuzzOptions) -> list[str]:
    payloads: set[str] = set()

    if opts.bruteforce:
        payloads |= _bruteforce_payloads(url, opts)
    else:
        payloads |= _session_id_payloads(url, opts)

    if opts.static:
        payloads |= build_static_payloads(get_base_url(url), "/".join(get_path_parts(url)))
    if opts.dir_traversal:
        payloads |= _traversal_payloads(url)
    if opts.index_allocation:
        payloads |= _index_allocation_payloads(url)
    if opts.encoding_tricks:
        payloads |= _encoding_trick_payloads(url)
    if opts.xss:
        payloads |= _xss_payloads(url)

    result = list(payloads)

    if opts.shuffle:
        rng = random.Random(opts.seed) if opts.seed is not None else random.Random()
        rng.shuffle(result)
    else:
        result.sort()

    if opts.max_payloads and len(result) > opts.max_payloads:
        result = result[: opts.max_payloads]

    return result
