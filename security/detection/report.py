"""Plain-text rendering of a DetectionResult.

Evaluation (rules/engine) never formats output; this module only presents a
finished result. Output is ASCII only: any other character in evidence text is
shown as a backslash escape, so it prints safely on legacy Windows consoles.
"""

from __future__ import annotations

from security.models.schemas import DetectionResult, Finding
from security.timeline import format_gap
from security.utils.helpers import format_timestamp


def ascii_safe(text: str) -> str:
    """Replace non-ASCII characters with backslash escapes."""
    return text.encode("ascii", "backslashreplace").decode("ascii")


def _indicator_lines(finding: Finding) -> list[str]:
    grouped: dict[str, list[str]] = {}
    for match in finding.matched_indicators:
        parts = grouped.setdefault(match["indicator"], [])
        if "evidence_id" in match:
            field = f".{match['field']}" if match.get("field") else ""
            parts.append(f"{match['evidence_id']}{field}")
        elif "observed_failures" in match:
            parts.append(f"{match['observed_failures']} failures (threshold "
                         f"{match['threshold']} in {match['window_seconds']} s, "
                         f"max {match['max_failures_in_window']} in one window)")
        elif "finding_id" in match:
            parts.append(match["finding_id"])
    return [f"    {name}: {', '.join(parts)}" if parts else f"    {name}"
            for name, parts in grouped.items()]


def _finding_lines(finding: Finding) -> list[str]:
    span = ""
    if finding.first_seen and finding.last_seen:
        seconds = (finding.last_seen - finding.first_seen).total_seconds()
        span = f" ({format_gap(seconds).lstrip('+')})"
    when = (f"{format_timestamp(finding.first_seen)} -> "
            f"{format_timestamp(finding.last_seen)}{span}") if finding.first_seen else "-"
    lines = [
        f"{finding.finding_id}  {finding.title}  [{finding.rule_id}]",
        f"  Severity   : {finding.severity.value}    Confidence: {finding.confidence.value}",
        f"  When       : {when}",
        f"  Device/User: {finding.device} / {finding.user or '-'}",
        f"  Reason     : {finding.reason}",
        f"  Details    : {finding.description}",
        "  Indicators :",
        *_indicator_lines(finding),
        f"  Events     : {', '.join(finding.supporting_events)}",
        f"  Records    : {', '.join(finding.evidence_sources)}",
        f"  Files      : {', '.join(finding.evidence_files)}",
        "  Severity because:",
        *[f"    - {factor}" for factor in finding.severity_factors],
        "  Confidence because:",
        *[f"    - {factor}" for factor in finding.confidence_factors],
    ]
    return lines


def format_detection(result: DetectionResult) -> str:
    """Render rules run, findings and data gaps as ASCII text."""
    lines = [
        f"Case ID  : {result.case_id or '-'}",
        f"Events   : {result.event_count}",
        f"Findings : {len(result.findings)}"
        + (f" ({result.duplicates_removed} duplicate(s) removed)"
           if result.duplicates_removed else ""),
        "",
        "Rules:",
    ]
    for rule in result.rules:
        lines.append(f"  {rule.rule_id}  {rule.rule_name}: examined "
                     f"{rule.events_considered} event(s), {rule.findings} finding(s), "
                     f"{len(rule.data_gaps)} data gap(s)")
    for finding in result.findings:
        lines += ["", *_finding_lines(finding)]
    if not result.findings:
        lines += ["", "No findings. (Check the data gaps below: a rule that could not "
                      "evaluate something has not ruled it out.)"]
    gap_rules = [r for r in result.rules if r.data_gaps]
    if gap_rules:
        lines += ["", "Data gaps (things a rule could not evaluate; not negative results):"]
        for rule in gap_rules:
            lines += [f"  {rule.rule_id}:", *[f"    - {gap}" for gap in rule.data_gaps]]
    return ascii_safe("\n".join(lines))
