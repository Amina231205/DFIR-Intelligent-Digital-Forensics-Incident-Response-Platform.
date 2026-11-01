"""DET-001: possible brute-force logon attempts.

HOW EVENTS ARE GROUPED AND COUNTED
----------------------------------
Only ``logon_failed`` events are considered. Each one is placed in a group
identified by THREE fields, all compared case-insensitively:

    (device, target account, source address)

* target account = the event's ``user`` (Windows ``TargetUserName``)
* source address = ``details.source_ip`` (Windows ``IpAddress``)

Failures for different accounts, from different sources, or on different
devices are never combined. A failure with no target account is skipped. A
failure with no source address is skipped too (the "same source" condition
cannot be checked) unless ``include_events_without_source`` is on; either way
it is reported under ``data_gaps`` rather than silently ignored.

Inside a group, failures are sorted by time and a "burst" is found with a
sliding window: any run of at least ``threshold`` failures whose first and last
timestamps are at most ``window_seconds`` apart (both inclusive). Overlapping
windows are merged into ONE burst, so a long attack yields one finding, not
one per window. A burst is a set of failures; a failure belongs to at most one
finding of this rule.

CORRELATION WITH A SUCCESSFUL LOGON
-----------------------------------
A ``logon_success`` is linked to a burst only when ALL of these hold: same
device, same account, same source address (known on both sides), and it occurs
between the last failure and ``success_window_seconds`` later. If a candidate
success exists but has no source address, the result is "unverifiable", not
"no".
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from datetime import timedelta
from typing import Any, Optional

from security.detection.base import (
    Rule, RuleContext, RuleOutput, build_finding, format_ids, raise_severity)
from security.detection.config import BruteForceConfig
from security.detection.ip_policy import IpClass, classify_ip
from security.models.schemas import (
    Confidence, EventType, Finding, NormalizedEvent, Severity)
from security.utils.helpers import format_timestamp


@dataclass(frozen=True)
class Burst:
    """Failures ``start..end`` (inclusive indexes) that form one burst."""

    start: int
    end: int
    max_in_window: int


def find_bursts(times: list, threshold: int, window_seconds: float) -> list[Burst]:
    """Find bursts in a chronologically sorted list of timestamps.

    A window starting at failure ``i`` contains every failure up to ``j``
    where ``times[j] - times[i] <= window_seconds``. It qualifies when it
    holds at least ``threshold`` failures. Overlapping qualifying windows are
    merged; windows that merely touch (the next one starts after the previous
    one ends) stay separate.
    """
    window = timedelta(seconds=window_seconds)
    qualifying: list[tuple[int, int, int]] = []
    j = 0
    for i in range(len(times)):
        j = max(j, i)
        while j + 1 < len(times) and times[j + 1] - times[i] <= window:
            j += 1
        if j - i + 1 >= threshold:
            qualifying.append((i, j, j - i + 1))
    merged: list[tuple[int, int, int]] = []
    for start, end, count in qualifying:
        if merged and start <= merged[-1][1]:
            previous = merged[-1]
            merged[-1] = (previous[0], max(previous[1], end), max(previous[2], count))
        else:
            merged.append((start, end, count))
    return [Burst(*item) for item in merged]


def _source(event: NormalizedEvent) -> Optional[str]:
    value = event.details.get("source_ip")
    text = value.strip() if isinstance(value, str) else None
    return text or None


class BruteForceRule(Rule):
    rule_id = "DET-001"
    name = "Possible Brute-Force Logon Attempts"

    def __init__(self, config: Optional[BruteForceConfig] = None) -> None:
        self.config = config or BruteForceConfig()

    def evaluate(self, context: RuleContext) -> RuleOutput:
        cfg = self.config
        failures = [e for e in context.events if e.event_type is EventType.LOGON_FAILED]
        successes = [e for e in context.events if e.event_type is EventType.LOGON_SUCCESS]

        groups: dict[tuple, list[NormalizedEvent]] = {}
        no_account: list[str] = []
        no_source: list[str] = []
        invalid_sources: set[str] = set()
        for event in failures:
            source = _source(event)
            if not event.user:
                no_account.append(event.event_id)
                continue
            if source is None and not cfg.include_events_without_source:
                no_source.append(event.event_id)
                continue
            if source and classify_ip(source) is IpClass.INVALID:
                invalid_sources.add(source)
            key = (event.device.casefold(), event.user.casefold(),
                   source.casefold() if source else None)
            groups.setdefault(key, []).append(event)

        gaps: list[str] = []
        if no_account:
            gaps.append(
                f"{len(no_account)} failed logon(s) have no target account and "
                f"were not evaluated: {format_ids(no_account)}")
        if no_source:
            gaps.append(
                f"{len(no_source)} failed logon(s) have no source address, so "
                "'same source' cannot be established; not grouped (set "
                f"include_events_without_source to group them): {format_ids(no_source)}")
        for value in sorted(invalid_sources):
            gaps.append(f"source value {value!r} is not a valid IP address; "
                        "failures were grouped by that text")

        findings: list[Finding] = []
        for key in sorted(groups, key=lambda k: (k[0], k[1], k[2] or "")):
            events = groups[key]
            bursts = find_bursts([e.timestamp for e in events], cfg.threshold,
                                 cfg.window_seconds)
            for burst in bursts:
                findings.append(self._finding(
                    context, successes, events[burst.start:burst.end + 1], burst))
        findings.sort(key=lambda f: (f.first_seen, f.supporting_events))
        return RuleOutput(findings, len(failures), gaps)

    # ------------------------------------------------------------------
    def _finding(self, context: RuleContext, successes: list[NormalizedEvent],
                 events: list[NormalizedEvent], burst: Burst) -> Finding:
        cfg = self.config
        first, last = events[0], events[-1]
        account, device, source = first.user, first.device, _source(first)
        count = len(events)
        span = round((last.timestamp - first.timestamp).total_seconds(), 6)

        status, success = self._success(successes, device, account, source, last)
        severity = raise_severity(Severity.MEDIUM, 1 if status == "yes" else 0)
        severity_factors = ["base level for a threshold-met failed-logon burst: Medium"]
        if status == "yes":
            severity_factors.append(
                "+1: a successful logon for the same account from the same source "
                "followed the failures")

        confidence = Confidence.MEDIUM
        confidence_factors = [
            f"{count} failed logons recorded directly in the Windows Security log "
            f"(threshold {cfg.threshold}): Medium"]
        if source is None:
            confidence = Confidence.LOW
            confidence_factors.append(
                "lowered to Low: events have no source address, so 'same source' "
                "is not established")
        elif count >= 2 * cfg.threshold:
            confidence = Confidence.HIGH
            confidence_factors.append(
                f"raised to High: failure count is at least twice the threshold "
                f"({2 * cfg.threshold})")

        reasons = Counter(e.details.get("failure_reason") or "unknown" for e in events)
        logon_types = sorted({e.details.get("logon_type_name")
                              or (f"type {e.details['logon_type']}"
                                  if e.details.get("logon_type") is not None else "unknown")
                              for e in events})
        source_class = classify_ip(source)
        indicators: list[dict[str, Any]] = [{
            "indicator": "repeated_failed_logons",
            "description": "failed logons for one account from one source inside "
                           "the configured window",
            "observed_failures": count,
            "threshold": cfg.threshold,
            "window_seconds": cfg.window_seconds,
            "max_failures_in_window": burst.max_in_window,
            "span_seconds": span,
        }]
        supporting = list(events)
        ctx: dict[str, Any] = {
            "grouping": {"device": device, "target_account": account,
                         "source_ip": source},
            "threshold": cfg.threshold,
            "window_seconds": cfg.window_seconds,
            "failure_count": count,
            "max_failures_in_window": burst.max_in_window,
            "first_failure": format_timestamp(first.timestamp),
            "last_failure": format_timestamp(last.timestamp),
            "span_seconds": span,
            "source_ip_class": source_class.value,
            "logon_types": logon_types,
            "failure_reasons": dict(sorted(reasons.items())),
            "followed_by_successful_logon": status,
            "success_window_seconds": cfg.success_window_seconds,
            "successful_logon_event_id": None,
            "seconds_to_successful_logon": None,
        }
        description = (
            f"{count} failed logons for account '{account}' from "
            f"{source or 'an unknown source'} on {device} between "
            f"{format_timestamp(first.timestamp)} and {format_timestamp(last.timestamp)} "
            f"({span:g} s; threshold {cfg.threshold} within {cfg.window_seconds} s).")
        if status == "yes" and success is not None:
            delay = round((success.timestamp - last.timestamp).total_seconds(), 6)
            supporting.append(success)
            ctx["successful_logon_event_id"] = success.event_id
            ctx["seconds_to_successful_logon"] = delay
            indicators.append({
                "indicator": "followed_by_successful_logon",
                "description": "successful logon, same device/account/source, after "
                               "the last failure",
                "event_id": success.event_id,
                "evidence_id": success.evidence_id,
                "evidence_file": success.evidence_file,
                "seconds_after_last_failure": delay,
                "success_window_seconds": cfg.success_window_seconds,
            })
            description += (f" A successful logon for the same account from the "
                            f"same source followed {delay:g} s after the last failure.")
        elif status == "unverifiable":
            description += (" A successful logon for the same account followed but "
                            "has no source address, so it cannot be linked.")
        reason = (
            f"Threshold met: {count} failed logons (>= {cfg.threshold}) within a "
            f"{cfg.window_seconds} s window for the same device, account and source "
            "address.")
        return build_finding(
            self, context, severity=severity, confidence=confidence, device=device,
            user=account, description=description, reason=reason,
            supporting=supporting, matched_indicators=indicators,
            finding_context=ctx, severity_factors=severity_factors,
            confidence_factors=confidence_factors)

    def _success(self, successes: list[NormalizedEvent], device: str, account: str,
                 source: Optional[str], last: NormalizedEvent):
        """('yes'|'no'|'unverifiable', matching success event or None)."""
        limit = last.timestamp + timedelta(seconds=self.config.success_window_seconds)
        candidates = [
            s for s in successes
            if s.device.casefold() == device.casefold()
            and s.user and s.user.casefold() == account.casefold()
            and last.timestamp <= s.timestamp <= limit]
        if source is not None:
            for s in candidates:
                other = _source(s)
                if other and other.casefold() == source.casefold():
                    return "yes", s
        if candidates and (source is None or any(_source(s) is None for s in candidates)):
            return "unverifiable", None
        return "no", None
