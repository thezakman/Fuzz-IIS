from __future__ import annotations

import argparse
import logging
import sys

from rich.console import Console

from . import __version__
from .banner import print_banner
from .config import load_config
from .engine import RunConfig, build_task_matrix, run
from .filters import MatchFilter
from .http_client import HttpConfig
from .output import ConsoleReporter, FileWriter, infer_format
from .payloads.builder import FuzzOptions
from .payloads.session_patterns import BASE_PATTERNS
from .utils import load_headers_file, load_lines_file, parse_cookie_string, parse_header_line, parse_methods

EXAMPLES = """\
examples:
  # basic cookieless session-id fuzzing
  iisfuzz https://target/app/secret.dll

  # add bruteforce word-splitting + directory traversal + more pattern variety
  iisfuzz https://target/app/secret.dll -b -dt --vary 20

  # test native access-control bypass headers (combined, then one-by-one)
  iisfuzz https://target/app/secret.dll -bh
  iisfuzz https://target/app/secret.dll -bh -th

  # only show interesting responses, write JSON, resume-safe
  iisfuzz https://target/app/secret.dll -fc 404 -mc 200 301 302 \\
      -o results.json --resume run1.resume

  # scan many targets through a proxy, 40 threads, capped request rate
  iisfuzz -L targets.txt -p http://127.0.0.1:8080 -t 40 --rate 25
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="iisfuzz",
        description="ASP.NET / IIS cookieless-session fuzzer and native access-control bypass tester.",
        epilog=EXAMPLES,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("url", nargs="?", help="Target URL to test")
    parser.add_argument("-L", "--list", dest="url_list", metavar="FILE",
                         help="File with one target URL per line")
    parser.add_argument("--config", metavar="FILE", help="Path to a TOML config file")
    parser.add_argument("--version", action="version", version=f"iisfuzz {__version__}")

    payload = parser.add_argument_group("payload generation")
    payload.add_argument("-f", "--fuzz-mode", choices=["single", "double", "both"], default="both",
                          help="Insert 1 pattern per position, 2, or both")
    payload.add_argument("--patterns-file", metavar="FILE",
                          help="Custom session-pattern wordlist (replaces the built-in list)")
    payload.add_argument("--vary", type=int, default=0, metavar="N",
                          help="Add N randomized session-munge patterns for extra variation")
    payload.add_argument("--max-x-length", type=int, default=6, metavar="N",
                          help="Max random token length used by --vary")
    payload.add_argument("-b", "--bruteforce", action="store_true",
                          help="Enable word-splitting bruteforce mutation of path segments")
    payload.add_argument("--min-word-length", type=int, default=4, metavar="N",
                          help="Minimum path-segment length to mutate under --bruteforce")
    payload.add_argument("-dt", "--dir-traversal", action="store_true",
                          help="Add directory-traversal payloads")
    payload.add_argument("-et", "--encoding-tricks", action="store_true",
                          help="Add whole-path normalization / WAF-evasion payloads")
    payload.add_argument("-ia", "--index-allocation", action="store_true",
                          help="Add NTFS $INDEX_ALLOCATION / ADS payloads")
    payload.add_argument("-x", "--xss", action="store_true",
                          help="Add ASP.NET-specific XSS / request-validation-bypass payloads")
    payload.add_argument("--no-static", dest="static", action="store_false",
                          help="Disable the built-in DuoDrop-style static bypass shapes")
    payload.add_argument("--shuffle", action="store_true", help="Randomize request order (default: sorted)")
    payload.add_argument("--max-payloads", type=int, default=None, metavar="N",
                          help="Cap the number of generated payloads")
    payload.add_argument("--dry-run", action="store_true",
                          help="Only print how many requests would be sent, then exit")

    http = parser.add_argument_group("http")
    http.add_argument("-t", "--threads", type=int, default=15, help="Concurrent worker threads")
    http.add_argument("--rate", type=float, default=0.0, metavar="REQ/S",
                       help="Global request-rate cap (0 = unlimited)")
    http.add_argument("-d", "--delay", type=float, default=0.0, metavar="SECONDS",
                       help="Extra fixed delay per request on top of --rate")
    http.add_argument("--timeout", type=float, default=8.0, help="Per-request timeout in seconds")
    http.add_argument("--retries", type=int, default=2, help="Retries on connection errors / 5xx")
    http.add_argument("--backoff", type=float, default=0.3, help="Retry backoff factor")
    http.add_argument("-m", "--method", default="GET", metavar="METHOD[,METHOD...]",
                       help="HTTP method(s) to test, comma-separated")
    http.add_argument("-p", "--proxy", help="Proxy URL, e.g. http://127.0.0.1:8080")
    http.add_argument("-k", "--insecure", action="store_true", help="Disable TLS certificate verification")
    http.add_argument("-A", "--user-agent", help="Pin a fixed User-Agent (default: random per request)")
    http.add_argument("-H", "--header", action="append", metavar="'Name: value'",
                       help="Extra static header, repeatable")
    http.add_argument("--cookie", metavar="'a=1; b=2'", help="Extra cookies as a raw Cookie string")
    http.add_argument("--no-default-cookies", action="store_true",
                       help="Don't send the built-in dummy ASP.NET/auth cookies")
    http.add_argument("-bh", "--bypass-headers", action="store_true",
                       help="Send access-control bypass headers (X-Original-URL, X-Forwarded-For, ...)")
    http.add_argument("-th", "--test-headers", action="store_true",
                       help="Test each bypass header individually instead of all combined")
    http.add_argument("--headers-file", metavar="FILE",
                       help="Custom bypass-header wordlist ('Name: value' per line), replaces the built-in set")
    http.add_argument("--follow-redirects", action="store_true", help="Follow HTTP redirects")
    http.add_argument("--max-body-bytes", type=int, default=262_144, metavar="N",
                       help="Cap bytes read per response body")
    http.add_argument("--no-baseline", action="store_true", help="Skip the baseline request to the raw URL")

    match = parser.add_argument_group("match / filter")
    match.add_argument("-mc", "--match-status", type=int, nargs="+", metavar="CODE")
    match.add_argument("-fc", "--filter-status", type=int, nargs="+", metavar="CODE")
    match.add_argument("-ml", "--match-length", type=int, nargs="+", metavar="N")
    match.add_argument("-fl", "--filter-length", type=int, nargs="+", metavar="N")
    match.add_argument("-mr", "--match-regex", metavar="REGEX", help="Only report if body matches REGEX")
    match.add_argument("-fr", "--filter-regex", metavar="REGEX", help="Drop results whose body matches REGEX")
    match.add_argument("-cs", "--content-sample", action="store_true", help="Include a body sample in results")
    match.add_argument("--sample-length", type=int, default=100, help="Body sample length in characters")

    out = parser.add_argument_group("output")
    out.add_argument("-o", "--output", metavar="FILE", help="Write matched results to FILE")
    out.add_argument("--format", choices=["console", "json", "jsonl", "csv", "txt"], default="console",
                      help="Output file format (default: inferred from --output extension)")
    out.add_argument("-v", "--verbose", action="store_true", help="Also show non-matching results")
    out.add_argument("-q", "--quiet", action="store_true", help="Only print matches, suppress banner/info lines")
    out.add_argument("-a", "--all-matches", dest="all_matches", action="store_true",
                     help="In the effect summary, list EVERY payload that reached each effect (not just one example)")
    out.add_argument("--no-color", action="store_true", help="Disable colored output")
    out.add_argument("--no-banner", action="store_true", help="Don't print the banner")
    out.add_argument("-l", "--log", metavar="FILE", help="Log INFO-level events to FILE (python logging)")

    misc = parser.add_argument_group("misc")
    misc.add_argument("--resume", metavar="FILE", help="Checkpoint file to allow resuming an interrupted run")
    misc.add_argument("--seed", type=int, help="Random seed, for reproducible --vary/--shuffle output")

    return parser


def _load_targets(args) -> list[str]:
    if args.url_list:
        return load_lines_file(args.url_list)
    if args.url:
        return [args.url]
    return []


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    parser = build_parser()

    # Pre-pass: only look for --config so its values can seed the real defaults.
    pre, _ = parser.parse_known_args(argv)
    config_overrides = load_config(pre.config)
    if config_overrides:
        parser.set_defaults(**config_overrides)

    args = parser.parse_args(argv)

    targets = _load_targets(args)
    if not targets:
        parser.error("provide a target URL or -L/--list FILE")

    console = Console(no_color=args.no_color, quiet=False)

    if not args.no_banner and not args.quiet:
        print_banner(console)

    if args.log:
        logging.basicConfig(filename=args.log, level=logging.INFO,
                             format="%(asctime)s - %(levelname)s - %(message)s")

    patterns = load_lines_file(args.patterns_file) if args.patterns_file else list(BASE_PATTERNS)
    opts = FuzzOptions(
        fuzz_mode=args.fuzz_mode,
        patterns=patterns,
        vary=args.vary,
        max_x_length=args.max_x_length,
        bruteforce=args.bruteforce,
        min_word_length=args.min_word_length,
        dir_traversal=args.dir_traversal,
        encoding_tricks=args.encoding_tricks,
        index_allocation=args.index_allocation,
        xss=args.xss,
        static=args.static,
        shuffle=args.shuffle,
        max_payloads=args.max_payloads,
        seed=args.seed,
    )

    extra_headers = {}
    for raw in args.header or []:
        parsed = parse_header_line(raw)
        if parsed:
            extra_headers[parsed[0]] = parsed[1]

    cfg = RunConfig(
        methods=parse_methods(args.method),
        bypass_headers=args.bypass_headers or args.test_headers,
        test_headers=args.test_headers,
        custom_bypass_headers=load_headers_file(args.headers_file) if args.headers_file else None,
        extra_headers=extra_headers,
        use_default_cookies=not args.no_default_cookies,
        extra_cookies=parse_cookie_string(args.cookie) if args.cookie else {},
        fixed_user_agent=args.user_agent,
        threads=max(1, args.threads),
        rate=args.rate,
        delay=args.delay,
        max_body_bytes=args.max_body_bytes,
        content_sample=args.content_sample,
        sample_length=args.sample_length,
        baseline=not args.no_baseline,
        follow_redirects=args.follow_redirects,
        resume_path=args.resume,
        seed=args.seed,
    )

    http_cfg = HttpConfig(
        timeout=args.timeout,
        retries=args.retries,
        backoff=args.backoff,
        verify_ssl=not args.insecure,
        proxy=args.proxy,
        pool_size=max(20, cfg.threads),
    )

    if args.insecure:
        console.print("[yellow][!] TLS certificate verification disabled[/yellow]")
    if cfg.bypass_headers and not args.quiet:
        console.print("[yellow][!] Bypass headers enabled — may trigger WAF/IDS detection[/yellow]")

    match_filter = MatchFilter.from_args(args)

    if args.dry_run:
        for target in targets:
            tasks = build_task_matrix(target, opts, cfg)
            console.print(f"[cyan][*] {target}: {len(tasks)} requests would be sent[/cyan]")
        return 0

    reporter = ConsoleReporter(console, verbose=args.verbose, quiet=args.quiet,
                               content_sample=args.content_sample, show_all=args.all_matches)
    writer = None
    if args.output:
        writer = FileWriter(args.output, infer_format(args.output, args.format))

    try:
        for target in targets:
            run(target, opts, cfg, http_cfg, match_filter, console, reporter, writer)
    except KeyboardInterrupt:
        if writer:
            writer.close()
        return 130

    reporter.summary()
    if writer:
        writer.close()
        console.print(f"[cyan][*] Results written to {args.output}[/cyan]")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
