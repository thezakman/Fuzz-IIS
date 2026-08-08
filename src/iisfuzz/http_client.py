"""HTTP session factory.

Each worker thread gets its own pooled ``requests.Session`` (via
``threading.local``) instead of the old behaviour of calling
``requests.request(...)`` fresh for every payload, which opened a brand new
TCP/TLS connection per request. Sessions also carry a retry-with-backoff
adapter so transient network errors don't kill a long fuzzing run.
"""
from __future__ import annotations

import threading

import requests
import urllib3
from requests.adapters import HTTPAdapter

try:
    from urllib3.util.retry import Retry
except ImportError:  # pragma: no cover - very old urllib3
    from requests.packages.urllib3.util.retry import Retry

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_local = threading.local()


class HttpConfig:
    def __init__(
        self,
        timeout: float = 8.0,
        retries: int = 2,
        backoff: float = 0.3,
        verify_ssl: bool = True,
        proxy: str | None = None,
        pool_size: int = 20,
    ):
        self.timeout = timeout
        self.retries = retries
        self.backoff = backoff
        self.verify_ssl = verify_ssl
        self.proxy = proxy
        self.pool_size = pool_size


def _build_session(cfg: HttpConfig) -> requests.Session:
    session = requests.Session()
    retry = Retry(
        total=cfg.retries,
        connect=cfg.retries,
        read=cfg.retries,
        backoff_factor=cfg.backoff,
        status_forcelist=(500, 502, 503, 504),
        allowed_methods=None,
        raise_on_status=False,
    )
    adapter = HTTPAdapter(
        max_retries=retry,
        pool_connections=cfg.pool_size,
        pool_maxsize=cfg.pool_size,
    )
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.verify = cfg.verify_ssl
    if cfg.proxy:
        session.proxies = {"http": cfg.proxy, "https": cfg.proxy}
    return session


def get_session(cfg: HttpConfig) -> requests.Session:
    cached = getattr(_local, "session", None)
    cached_cfg = getattr(_local, "cfg_id", None)
    if cached is not None and cached_cfg == id(cfg):
        return cached
    session = _build_session(cfg)
    _local.session = session
    _local.cfg_id = id(cfg)
    return session
