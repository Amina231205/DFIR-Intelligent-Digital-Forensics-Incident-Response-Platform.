"""Rule framework: the contract every detection rule follows.

A rule is a small class with an id, a name and ``evaluate(context)``. It
receives the whole chronological event list (read-only) and returns findings
plus an account of what it could not evaluate. Rules do NOT format output and
do NOT assign finding ids; the engine does both, so adding a rule never
touches reporting.

Severity / confidence vocabulary used by all rules (see docs/DETECTION.md):

* Severity is raised one step per documented aggravating factor, starting from
  the rule's base level, and is capped at HIGH in this phase. CRITICAL is
  reserved for confirmed impact and is never assigned automatically.
* Confidence says how sure we are that the rule's stated conditions are
  really met and linked correctly. It is NOT the probability of malicious
  intent.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, ClassVar, Iterable, Optional

from security.models.schemas import Confidence, Finding, NormalizedEvent, Severity
from security.normalization import event_sort_key

_SEVERITY_STEPS = [Severity.LOW, Severity.MEDIUM, Severity.HIGH]


@dataclass
class RuleContext:
    """Everything a rule may read. Treat all of it as read-only."""

    events: list[NormalizedEvent]                 # chronological
    now: datetime                                  # analysis time (detected_at)
    case_id: Optional[str] = None
    prior_findings: list[Finding] = field(default_factory=list)   # earlier rules
    rules_run: list[str] = field(default_factory=list)            # their rule ids


@dataclass
class RuleOutput:
    """Result of one rule: findings (without ids) and what it could not check."""

    findings: list[Finding] = field(default_factory=list)
    events_considered: int = 0
    data_gaps: list[str] = field(default_factory=list)


class Rule(ABC):
    """Base class for detection rules."""

    rule_id: ClassVar[str]
    name: ClassVar[str]

    @abstractmethod
    def evaluate(self, context: RuleContext) -> RuleOutput:
        """Examine ``context.events`` and return findings (ids are assigned later)."""


# ------------------------------------------------------------------ helpers
def raise_severity(base: Severity, steps: int) -> Severity:
    """Raise ``base`` by ``steps`` levels, never beyond HIGH."""
    index = _SEVERITY_STEPS.index(base) + max(steps, 0)
    return _SEVERITY_STEPS[min(index, len(_SEVERITY_STEPS) - 1)]


def users_compatible(first: Optional[str], second: Optional[str]) -> bool:
    """True unless both users are known and different (case-insensitive).

    An unknown user can neither confirm nor rule out a link, so it is
    compatible; callers record that the user could not be checked.
    """
    return not (first and second and first.casefold() != second.casefold())


def format_ids(ids: Iterable[str], limit: int = 10) -> str:
    """'E-1, E-2, E-3 (+4 more)' for readable data-gap messages."""
    items = list(ids)
    shown = ", ".join(items[:limit])
    return shown + (f" (+{len(items) - limit} more)" if len(items) > limit else "")


def snippet(text: str, limit: int = 80) -> str:
    """Single-line, length-limited excerpt for matched-indicator evidence."""
    flat = " ".join(str(text).split())
    return flat if len(flat) <= limit else flat[: limit - 3] + "..."


def build_finding(
    rule: Rule,
    context: RuleContext,
    *,
    severity: Severity,
    confidence: Confidence,
    device: str,
    user: Optional[str],
    description: str,
    reason: str,
    supporting: Iterable[NormalizedEvent],
    matched_indicators: list[dict[str, Any]],
    finding_context: dict[str, Any],
    severity_factors: list[str],
    confidence_factors: list[str],
    extra_evidence: Iterable[tuple[str, str]] = (),
) -> Finding:
    """Assemble a Finding with full evidence traceability.

    ``supporting`` is de-duplicated and ordered chronologically (same total
    order as the timeline). ``extra_evidence`` lists (record_id, file) pairs
    for raw records the rule relied on that are NOT timeline events, such as
    the users.json account record behind an "is administrator" fact.
    ``finding_id`` is left empty; the engine assigns it.
    """
    unique = {event.event_id: event for event in supporting}
    ordered = sorted(unique.values(), key=event_sort_key)
    extras = sorted(set(extra_evidence))
    sources = [e.evidence_id for e in ordered]
    sources += [rid for rid, _ in extras if rid not in sources]
    return Finding(
        finding_id="",
        rule_id=rule.rule_id,
        title=rule.name,
        severity=severity,
        confidence=confidence,
        device=device,
        user=user,
        description=description,
        reason=reason,
        detected_at=context.now,
        first_seen=ordered[0].timestamp if ordered else None,
        last_seen=ordered[-1].timestamp if ordered else None,
        supporting_events=[e.event_id for e in ordered],
        evidence_sources=sources,
        severity_factors=severity_factors,
        confidence_factors=confidence_factors,
        rule_name=rule.name,
        evidence_files=sorted({e.evidence_file for e in ordered}
                              | {name for _, name in extras}),
        matched_indicators=matched_indicators,
        context=finding_context,
    )
