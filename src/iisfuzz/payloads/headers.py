"""Basic request headers and access-control bypass header templates."""
from __future__ import annotations

import random
from urllib.parse import urlparse

from ..utils import random_user_agent

BASE_ACCEPT_HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate",
    "Connection": "keep-alive",
}

# Static values only; dynamic ones (X-Original-URL, X-Forwarded-Host, ...) are
# filled in per-request by get_bypass_headers().
BYPASS_HEADERS_TEMPLATE = {
    "X-Original-URL": None,
    "X-Rewrite-URL": None,
    "X-Forwarded-For": "127.0.0.1",
    "X-Forward-For": "127.0.0.1",
    "X-Forwarded-Host": None,
    "X-Custom-IP-Authorization": "127.0.0.1",
    "X-ProxyUser-Ip": "127.0.0.1",
    "True-Client-IP": "127.0.0.1",
    "CF-Connecting-IP": "127.0.0.1",
    "X-Real-IP": "127.0.0.1",
    "X-AppPool-ID": "DefaultAppPool",
    "X-WebApp-Name": "Root",
    "ASP.NET_SessionId": "dummy_session",
    "X-AspNet-Version": "4.0.30319",
    "X-PoweredBy": "ASP.NET",
    "X-AspNetMvc-Version": "5.2",
    "X-Handler": "*.aspx",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
}

DEFAULT_COOKIES = {
    "ASP.NET_SessionId": "dummy_session_id",
    ".ASPXAUTH": "dummy_auth_token",
    "ViewState": "dummy_viewstate",
    "CustomCookie": "bypass_cookie",
    "X-Custom-Cookie": "bypass_value",
}


def get_basic_headers(fixed_user_agent: str | None, rng: random.Random | None = None) -> dict:
    headers = dict(BASE_ACCEPT_HEADERS)
    headers["User-Agent"] = fixed_user_agent or random_user_agent(rng)
    return headers


def get_bypass_headers(url: str) -> dict:
    parsed = urlparse(url)
    headers = dict(BYPASS_HEADERS_TEMPLATE)
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    headers["X-Original-URL"] = path
    headers["X-Rewrite-URL"] = path
    headers["X-Forwarded-Host"] = parsed.netloc
    return headers
