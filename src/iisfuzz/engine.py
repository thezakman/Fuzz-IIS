"""The scanning engine: builds the task matrix and drives it through a thread pool."""
from __future__ import annotations

import random
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

import requests
from rich.live import Live
from rich.progress import BarColumn, Progress, TaskProgressColumn, TextColumn

from .filters import MatchFilter
from .http_client import HttpConfig, get_session
from .models import Finding
from .output import ConsoleReporter, FileWriter
from .payloads.builder import FuzzOptions, build_payloads
from .payloads.headers import DEFAULT_COOKIES, get_basic_headers, get_bypass_headers
from .ratelimit import RateLimiter
from .resume import ResumeState, task_key

DEFAULT_MAX_BODY_BYTES = 262_144  # 256 KiB cap per response body read


@dataclass
class RunConfig:
    methods: list[str] = field(default_factory=lambda: ["GET"])
    bypass_headers: bool = False
    test_headers: bool = False
    custom_bypass_headers: dict | None = None  # overrides the built-in template when set
    extra_headers: dict = field(default_factory=dict)
    use_default_cookies: bool = True
    extra_cookies: dict = field(default_factory=dict)
    fixed_user_agent: str | None = None
    threads: int = 15
    rate: float = 0.0
    delay: float = 0.0
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES
    content_sample: bool = False
    sample_length: int = 100
    baseline: bool = True
    follow_redirects: bool = False
    resume_path: str | None = None
    seed: int | None = None


def _header_variants(payload: str, cfg: RunConfig) -> list[tuple[str | None, dict]]:
    if not cfg.bypass_headers:
        return [(None, {})]

    bypass = cfg.custom_bypass_headers if cfg.custom_bypass_headers is not None else get_bypass_headers(payload)

    if not cfg.test_headers:
        return [("__combined__", dict(bypass))]

    return [(name, {name: value}) for name, value in bypass.items() if value is not None]


def _perform_request(
    session: requests.Session,
    method: str,
    url: str,
    headers: dict,
    cookies: dict,
    timeout: float,
    max_body_bytes: int,
    allow_redirects: bool,
) -> tuple[requests.Response | None, bytes, float, str | None]:
    start = time.monotonic()
    try:
        resp = session.request(
            method, url, headers=headers, cookies=cookies,
            allow_redirects=allow_redirects, timeout=timeout, stream=True,
        )
    except requests.exceptions.RequestException as exc:
        return None, b"", (time.monotonic() - start) * 1000, str(exc)

    body = bytearray()
    try:
        for chunk in resp.iter_content(chunk_size=8192):
            if not chunk:
                continue
            body.extend(chunk)
            if len(body) >= max_body_bytes:
                break
    except requests.exceptions.RequestException:
        pass
    finally:
        resp.close()

    elapsed_ms = (time.monotonic() - start) * 1000
    return resp, bytes(body), elapsed_ms, None


def _to_finding(
    method: str, url: str, resp, body: bytes, elapsed_ms: float, error: str | None,
    header_name: str | None, header_value, cfg: RunConfig,
) -> tuple[Finding, str]:
    if error is not None or resp is None:
        return Finding(target=url, method=method, error=error, header_name=header_name,
                        header_value=header_value), ""

    content_length_hdr = resp.headers.get("Content-Length")
    content_length = int(content_length_hdr) if content_length_hdr and content_length_hdr.isdigit() else len(body)
    body_text = body.decode(resp.encoding or "utf-8", errors="replace") if body else ""

    finding = Finding(
        target=url,
        method=method,
        status_code=resp.status_code,
        content_length=content_length,
        content_type=resp.headers.get("Content-Type", "N/A"),
        server=resp.headers.get("Server", "N/A"),
        elapsed_ms=round(elapsed_ms, 1),
        location=resp.headers.get("Location"),
        sample=body_text[: cfg.sample_length] if cfg.content_sample else None,
        header_name=header_name,
        header_value=header_value,
    )
    return finding, body_text


def capture_baseline(console, url: str, http_cfg: HttpConfig, basic_headers: dict, cookies: dict):
    """Fetch the raw target once, print it, and return (status, length) so the match
    filter can flag any payload whose response DIFFERS from it (the bypass oracle)."""
    session = get_session(http_cfg)
    resp, body, elapsed_ms, error = _perform_request(
        session, "GET", url, basic_headers, cookies, http_cfg.timeout,
        DEFAULT_MAX_BODY_BYTES, allow_redirects=False,
    )
    if error:
        console.print(f"[yellow][!] Baseline request failed: {error}[/yellow]")
        return None, None
    length = len(body)
    console.print(
        f"[cyan][*] Baseline: {url} -> {resp.status_code} "
        f"({length}B, {resp.headers.get('Content-Type', 'N/A')})[/cyan]"
    )
    return resp.status_code, length


def build_task_matrix(url: str, opts: FuzzOptions, cfg: RunConfig) -> list[tuple[str, str, str | None, dict]]:
    payloads = build_payloads(url, opts)
    tasks: list[tuple[str, str, str | None, dict]] = []
    for payload in payloads:
        for method in cfg.methods:
            for header_name, header_dict in _header_variants(payload, cfg):
                tasks.append((payload, method, header_name, header_dict))
    return tasks


def run(
    url: str,
    opts: FuzzOptions,
    cfg: RunConfig,
    http_cfg: HttpConfig,
    match_filter: MatchFilter,
    console,
    reporter: ConsoleReporter,
    writer: FileWriter | None,
) -> None:
    tasks = build_task_matrix(url, opts, cfg)
    console.print(f"[cyan][*] Generated {len(tasks)} requests for {url}[/cyan]")

    cookies = dict(DEFAULT_COOKIES) if cfg.use_default_cookies else {}
    cookies.update(cfg.extra_cookies)

    if cfg.baseline:
        b_status, b_length = capture_baseline(
            console, url, http_cfg, get_basic_headers(cfg.fixed_user_agent), cookies
        )
        # With no explicit -mc/-fc/-ml..., flag anything that differs from the baseline
        # (403 -> 200 = a real native-control bypass) instead of matching everything.
        if b_status is not None and match_filter.is_noop():
            match_filter.baseline_status = b_status
            match_filter.baseline_length = b_length
            console.print(
                "[cyan][*] Auto-match: flagging responses that differ from the baseline "
                f"({b_status}/{b_length}B). Override with -mc/-fc/-ml.[/cyan]"
            )

    resume = ResumeState(cfg.resume_path)
    if resume.completed_count:
        console.print(f"[cyan][*] Resume: {resume.completed_count} previously completed tasks on record[/cyan]")

    rate_limiter = RateLimiter(cfg.rate)
    rng = random.Random(cfg.seed) if cfg.seed is not None else random.Random()

    progress = Progress(
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
        transient=True,
    )

    def worker(payload: str, method: str, header_name: str | None, header_dict: dict):
        rate_limiter.wait()
        if cfg.delay:
            time.sleep(cfg.delay)
        headers = get_basic_headers(cfg.fixed_user_agent, rng)
        headers.update(cfg.extra_headers)
        headers.update(header_dict)
        session = get_session(http_cfg)
        resp, body, elapsed_ms, error = _perform_request(
            session, method, payload, headers, cookies, http_cfg.timeout,
            cfg.max_body_bytes, cfg.follow_redirects,
        )
        header_value = header_dict.get(header_name) if header_name and header_name != "__combined__" else None
        finding, body_text = _to_finding(
            method, payload, resp, body, elapsed_ms, error, header_name, header_value, cfg
        )
        return finding, body_text

    try:
        with Live(progress, refresh_per_second=10, console=console):
            task_id = progress.add_task("[cyan]Fuzzing...", total=len(tasks))
            executor = ThreadPoolExecutor(max_workers=cfg.threads)
            try:
                futures = {}
                for payload, method, header_name, header_dict in tasks:
                    key = task_key(method, header_name or "", payload)
                    if resume.is_done(key):
                        progress.update(task_id, advance=1)
                        continue
                    fut = executor.submit(worker, payload, method, header_name, header_dict)
                    futures[fut] = key

                for fut in as_completed(futures):
                    key = futures[fut]
                    finding, body_text = fut.result()
                    matched = match_filter.evaluate(finding, body_text)
                    finding.matched = matched
                    reporter.report(finding, matched)
                    if writer and matched:
                        writer.write(finding.as_dict())
                    resume.mark_done(key)
                    progress.update(task_id, advance=1)
                executor.shutdown(wait=True)
            except KeyboardInterrupt:
                executor.shutdown(wait=False, cancel_futures=True)
                raise
    except KeyboardInterrupt:
        console.print("\n[yellow][!] Interrupted — progress saved to resume file (if set).[/yellow]")
        raise
    finally:
        resume.close()
