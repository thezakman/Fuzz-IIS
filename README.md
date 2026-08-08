# iisfuzz

```
   .....
 .H8888888x.  '`+
:888888888888x.  !
8~    `"*88888888"
!      .  `f""""   ?88   d8P  d88888P  d88888P
 ~:...-` :8L <)88: d88   88      d8P'     d8P'
    .   :888:>X88! ?8b  ,88    d8P'     d8P'
 :~"88x 48888X ^`  `?88P'?8  bd88888P' d88888P'
<  :888k'88888X  ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
  d8888f '88888X  ▗▄▄▄▖▗▄▄▄▖ ▗▄▄▖
 :8888!    ?8888>   ▓    ▓  ▐▌    ╶Internet
 X888!      8888~   ▒    ▒   ▝▀▚▖ ╶Information
 '888       X88f   ▄█▄▖▗▄█▄▖▗▄▄▞▘ ╶Services
  '%8:     .8*"  ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
     ^----~"`     ▔▔Done by:▔TheZakMan▔▔v2.0.0▔

        "talk is cheap, show me the bug"
```

ASP.NET / IIS cookieless-session fuzzer and native access-control bypass
tester. Generates and probes the `(S(x))`-style cookieless session-munge
patterns (and related techniques) that IIS/ASP.NET historically use to
route requests, looking for places where inserting one into a URL changes
how access control, authentication, or `<location>` restrictions get
applied to the underlying resource.

> Authorized security testing only. Only point this at targets you own or
> have explicit written permission to test.

## Install

```bash
pipx install .
# or, for local development:
pip install -e .
```

Requires Python >= 3.9.

## Quick start

```bash
# basic cookieless session-id fuzzing
iisfuzz https://target/app/secret.dll

# add bruteforce word-splitting + directory traversal + more pattern variety
iisfuzz https://target/app/secret.dll -b -dt --vary 20

# test native access-control bypass headers (combined, then one-by-one)
iisfuzz https://target/app/secret.dll -bh
iisfuzz https://target/app/secret.dll -bh -th

# only show interesting responses, write JSON, resume-safe
iisfuzz https://target/app/secret.dll -fc 404 -mc 200 301 302 \
    -o results.json --resume run1.resume

# scan many targets through a proxy, 40 threads, capped request rate
iisfuzz -L targets.txt -p http://127.0.0.1:8080 -t 40 --rate 25

# see how many requests a config would send without sending any
iisfuzz https://target/app/secret.dll -b -dt -ia -x --dry-run
```

Run `iisfuzz --help` for the full, grouped flag reference.

## What it does

- **Payload generation** — cookieless session-munge patterns inserted at
  every path-segment boundary (single or double insertion), word-splitting
  bruteforce mutation of path segments, directory-traversal payloads,
  NTFS `::$INDEX_ALLOCATION` / ADS suffixes, whole-path
  normalization/WAF-evasion rewrites, ASP.NET-specific XSS payloads, and a
  built-in set of DuoDrop-style static bypass shapes (`web.config`,
  `App_Data`, `App_Code`, `bin`, ...). `--vary N` adds N randomized
  session-munge patterns on top of the fixed list for extra coverage
  across repeated runs.
- **Access-control bypass headers** — `-bh` sends the classic bypass
  header set (`X-Original-URL`, `X-Rewrite-URL`, `X-Forwarded-For`,
  `X-Forwarded-Host`, IP-spoofing headers, DuoDrop-style ASP.NET headers)
  either all at once or, with `-th`, one at a time so you can see which
  individual header actually flips the response.
- **Granular control** — per-run thread count, global request-rate cap,
  retries with backoff, TLS verification toggle, proxying, custom
  headers/cookies, multiple HTTP methods, custom pattern/header wordlists
  (`--patterns-file`, `--headers-file`), match/filter on status code,
  content length, or a response-body regex.
- **Robustness** — pooled per-thread HTTP sessions (not a fresh TCP/TLS
  connection per request), automatic retry with backoff on transient
  errors, a capped-read response body (`--max-body-bytes`) so a huge
  response can't blow up memory, and a `--resume` checkpoint file so a
  long run can be killed and continued without repeating work.
- **Output** — live colored console results by default, or structured
  `json`/`jsonl`/`csv`/`txt` export via `-o`/`--format`.

## Configuration file

Frequently-used defaults (proxy, threads, timeout, ...) can be pinned in a
TOML file instead of retyped every run:

```toml
# ~/.config/iisfuzz/config.toml
[http]
threads = 30
timeout = 10
proxy = "http://127.0.0.1:8080"
```

`iisfuzz` reads `~/.config/iisfuzz/config.toml` automatically if present,
or an explicit `--config path/to/file.toml`. Any flag passed on the
command line overrides the config file.
