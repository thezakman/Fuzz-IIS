"""Result rendering: live console output plus optional structured file export."""
from __future__ import annotations

import csv
import json
import os
import threading


def infer_format(path: str, explicit: str | None) -> str:
    if explicit and explicit != "console":
        return explicit
    ext = os.path.splitext(path)[1].lower().lstrip(".")
    if ext in ("json", "jsonl", "csv", "txt"):
        return ext
    return "json"


class ConsoleReporter:
    _PAYLOAD_CAP = 500  # bound how many payloads we retain per effect

    def __init__(self, console, verbose: bool = False, quiet: bool = False,
                 content_sample: bool = False, show_all: bool = False):
        self.console = console
        self.verbose = verbose
        self.quiet = quiet
        self.content_sample = content_sample
        self.show_all = show_all
        self.matched = 0
        self.errors = 0
        self.tested = 0
        # Collapse identical effects: many token variants ((S(x)), (A(x)), %2f...)
        # produce the exact same bypass response. Group by (status, length, type) so
        # they report as ONE finding with a ×N count instead of N redundant lines.
        # Each effect keeps the list of payloads that reached it (for --all-matches).
        self.effects: dict[tuple, dict] = {}

    def report(self, finding, matched: bool) -> None:
        self.tested += 1
        if finding.error is not None:
            self.errors += 1
            if self.verbose and not self.quiet:
                self.console.print(
                    f"[red][-] Error {finding.method} {finding.target}: {finding.error}[/red]"
                )
            return

        if matched:
            self.matched += 1
            sig = (finding.status_code, finding.content_length, finding.content_type)
            eff = self.effects.get(sig)
            if eff is not None:
                eff["count"] += 1
                if len(eff["payloads"]) < self._PAYLOAD_CAP:
                    eff["payloads"].append(finding.target)
                return  # same effect already shown — collapse the duplicate
            self.effects[sig] = {
                "count": 1, "example": finding.target,
                "status": finding.status_code, "length": finding.content_length,
                "type": finding.content_type, "payloads": [finding.target],
            }
            effect_num = len(self.effects)
            self.console.print(
                f"[bold green][+] NEW EFFECT #{effect_num}[/bold green] "
                f"[green]{finding.status_code}/{finding.content_length}B[/green] "
                "[dim](identical hits from other payloads are collapsed into this)[/dim]"
            )
            extra = ""
            if finding.header_name:
                extra = f"\n    Header: {finding.header_name}: {finding.header_value}"
            sample = ""
            if self.content_sample and finding.sample:
                sample = f"\n    Sample: {finding.sample}"
            loc = f"\n    Location: {finding.location}" if finding.location else ""
            self.console.print(
                f"[green][+] {finding.method} {finding.target}[/green]{extra}\n"
                f"    Status: {finding.status_code}  "
                f"Length: {finding.content_length}  "
                f"Type: {finding.content_type}  "
                f"Server: {finding.server}"
                f"{loc}{sample}"
            )
        elif self.verbose and not self.quiet:
            self.console.print(
                f"[yellow][-] {finding.method} {finding.target} -> "
                f"{finding.status_code} ({finding.content_length}B)[/yellow]"
            )

    def summary(self) -> None:
        unique = len(self.effects)
        self.console.print(
            f"\n[cyan][*] Done. Tested: {self.tested}  "
            f"Matched: {self.matched} request{'' if self.matched == 1 else 's'} "
            f"→ {unique} unique effect{'' if unique == 1 else 's'}  "
            f"Errors: {self.errors}[/cyan]"
        )
        if not self.effects:
            return
        # The effect table is the authoritative view: many payloads (e.g. the
        # (S(x))/(A(x))/%2f... cookieless token variants) usually produce the SAME
        # response — that is ONE primitive reached N ways, not N findings.
        noun = "bypass/primitive" if unique == 1 else "distinct bypasses/primitives"
        self.console.print(
            f"[cyan][*] {unique} {noun} — identical responses collapsed "
            "(× = how many payload variants reached the same effect):[/cyan]"
        )
        for i, eff in enumerate(sorted(self.effects.values(), key=lambda e: -e["count"]), 1):
            head = (
                f"    [bold]#{i}[/bold]  [green]{eff['status']}[/green]  {eff['length']}B  "
                f"{eff['type']}  [bold]×{eff['count']}[/bold]"
            )
            if self.show_all:
                # List every payload that reached this effect (for repro / reporting).
                self.console.print(head + ":")
                for p in eff["payloads"]:
                    self.console.print(f"        [green]{p}[/green]")
                if eff["count"] > len(eff["payloads"]):
                    self.console.print(
                        f"        [dim]... and {eff['count'] - len(eff['payloads'])} "
                        "more (retention cap reached)[/dim]"
                    )
            else:
                self.console.print(head + f"  e.g. {eff['example']}")


class FileWriter:
    """Streams JSONL directly; buffers JSON/CSV/TXT and flushes on close()."""

    def __init__(self, path: str, fmt: str):
        self.path = path
        self.fmt = fmt
        self._lock = threading.Lock()
        self._buffer: list[dict] = []
        self._fh = None
        if fmt == "jsonl":
            self._fh = open(path, "w", encoding="utf-8")

    def write(self, record: dict) -> None:
        with self._lock:
            if self.fmt == "jsonl":
                self._fh.write(json.dumps(record) + "\n")
            else:
                self._buffer.append(record)

    def close(self) -> None:
        with self._lock:
            if self.fmt == "jsonl":
                self._fh.close()
                return
            if self.fmt == "json":
                with open(self.path, "w", encoding="utf-8") as fh:
                    json.dump(self._buffer, fh, indent=2)
            elif self.fmt == "csv":
                if not self._buffer:
                    return
                keys = list(self._buffer[0].keys())
                with open(self.path, "w", newline="", encoding="utf-8") as fh:
                    writer = csv.DictWriter(fh, fieldnames=keys)
                    writer.writeheader()
                    writer.writerows(self._buffer)
            elif self.fmt == "txt":
                with open(self.path, "w", encoding="utf-8") as fh:
                    for r in self._buffer:
                        fh.write(
                            f"{r.get('method')} {r.get('target')} -> "
                            f"{r.get('status_code')} ({r.get('content_length')}B)"
                        )
                        if r.get("header_name"):
                            fh.write(f"  [{r['header_name']}: {r['header_value']}]")
                        fh.write("\n")
