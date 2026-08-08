"""Match / filter evaluation for scan results.

Semantics mirror ffuf-style tooling:
  * ``match_*``  -> keep ONLY results satisfying the condition (allow-list)
  * ``filter_*`` -> drop results satisfying the condition (block-list)
A result must pass every configured rule to be reported.
"""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass
class MatchFilter:
    match_status: set[int] | None = None
    filter_status: set[int] | None = None
    match_length: set[int] | None = None
    filter_length: set[int] | None = None
    match_regex: re.Pattern | None = None
    filter_regex: re.Pattern | None = None
    # Baseline signature of the raw target. When no explicit match/filter rule is
    # given, a result is flagged only when it DIFFERS from this baseline — which is
    # the real access-control-bypass oracle (e.g. 403 -> 200), not a fixed status.
    baseline_status: int | None = None
    baseline_length: int | None = None

    @classmethod
    def from_args(cls, args) -> "MatchFilter":
        return cls(
            match_status=set(args.match_status) if args.match_status else None,
            filter_status=set(args.filter_status) if args.filter_status else None,
            match_length=set(args.match_length) if args.match_length else None,
            filter_length=set(args.filter_length) if args.filter_length else None,
            match_regex=re.compile(args.match_regex, re.I) if args.match_regex else None,
            filter_regex=re.compile(args.filter_regex, re.I) if args.filter_regex else None,
        )

    def is_noop(self) -> bool:
        return not any(
            [
                self.match_status,
                self.filter_status,
                self.match_length,
                self.filter_length,
                self.match_regex,
                self.filter_regex,
            ]
        )

    def evaluate(self, finding, body: str | None = None) -> bool:
        if finding.error is not None:
            return True

        # No explicit rule from the user: fall back to the baseline-diff oracle so
        # the fuzzer flags a real bypass out of the box instead of needing -mc/-fc.
        if self.is_noop():
            if self.baseline_status is None:
                return True  # no baseline captured -> legacy "report everything"
            status = finding.status_code or 0
            base = self.baseline_status
            base_is_deny = base in (401, 403) or base >= 400
            resp_is_success = 200 <= status < 300
            # The bypass signal: a denied/errored resource now succeeds (403 -> 200).
            if base_is_deny and resp_is_success:
                return True
            # When the raw target is already accessible (baseline 2xx), flag a
            # content change (different length) or a status change — "what differs".
            if not base_is_deny:
                if status != base:
                    return True
                if self.baseline_length is not None and finding.content_length != self.baseline_length:
                    return True
            # Same-or-worse deny (403 -> 404, 403 -> different-length error page) is
            # NOT a bypass — suppress the noise.
            return False

        if self.match_status is not None and finding.status_code not in self.match_status:
            return False
        if self.filter_status is not None and finding.status_code in self.filter_status:
            return False
        if self.match_length is not None and finding.content_length not in self.match_length:
            return False
        if self.filter_length is not None and finding.content_length in self.filter_length:
            return False
        if self.match_regex is not None and not self.match_regex.search(body or ""):
            return False
        if self.filter_regex is not None and self.filter_regex.search(body or ""):
            return False
        return True
