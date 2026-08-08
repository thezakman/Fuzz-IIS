"""ASP.NET cookieless-session-id pattern payloads.

``BASE_PATTERNS`` are the well-known fixed cookieless munge patterns
(``(S(x))`` and friends) plus other in-URL session-token conventions seen in
the wild (ViewState, ASPSESSIONID, JSESSIONID...). ``iter_random_patterns``
adds variation on top: random-length tokens across a wider set of
single/double-letter munge codes and multi-part chained patterns, so repeat
runs don't all probe the exact same handful of literal strings.
"""
from __future__ import annotations

import random

from ..utils import random_string

BASE_PATTERNS = [
    "(S(x))",
    "(F(x))",
    "(L(x))",
    "(A(x))",
    "(Y(Z))",
    "(G(AAA-BBB))",
    "(D(CCC=DDD))",
    "(E(0-1))",
    "(XXXXXXXX)",
    "(A(XXXXXXXX)F(YYYYYYYY))",
    "(G(AAA-BBB)D(CCC=DDD)E(0-1))",
    "(ViewState=12345)",
    "(SessionId=ABCDE)",
    "(ASPSESSIONIDQGGQQSJJ=ABCDEFGHIJKLMNOP)",
    "(ASP.NET_SessionId=abcdefghijklmnopqrstuvwx)",
    "(JSESSIONID=A1B2C3D4E5F6G7H8I9J0)",
]

_LETTER_CODES = list("SLAYGVJKWHMNPQRTUXBCDEFIOZ") + [
    "AA", "BB", "CC", "DD", "EE", "FF", "GG", "HH",
]

_COMPLEX_TEMPLATES = [
    "G({0})D({1})E({2})",
    "A({0})F({1})",
    "V({0})Z({1})",
    "J({0})K({1})L({2})",
    "M({0})N({1})O({2})P({3})",
    "Q({0})R({1})S({2})T({3})U({4})",
]


def iter_random_patterns(count: int, max_x_length: int, rng: random.Random | None = None) -> list[str]:
    """Generate ``count`` randomized session-munge patterns for extra variation."""
    r = rng or random
    out: set[str] = set()
    attempts = 0
    while len(out) < count and attempts < count * 8:
        attempts += 1
        length = r.randint(1, max(1, max_x_length))
        if r.random() < 0.6:
            code = r.choice(_LETTER_CODES)
            out.add(f"({code}({random_string(length, r)}))")
        else:
            template = r.choice(_COMPLEX_TEMPLATES)
            slots = template.count("{")
            values = [random_string(length, r) for _ in range(slots)]
            out.add(f"({template.format(*values)})")
    return list(out)
