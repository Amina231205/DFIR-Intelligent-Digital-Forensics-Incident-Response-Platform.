"""Detection engine: run rules over a timeline and collect findings.

    from security.detection import detect_case
    result = detect_case("security/sample_evidence/INC-001")
    for finding in result.findings:
        print(finding.finding_id, finding.rule_id, finding.severity.value)

Behaviour:

* Input is a Phase 4 ``Timeline``; events are copied out of it and rules
  receive them read-only. Nothing is written anywhere.
* Rules run in order. Finding ids (``F-001`` ...) are assigned as each rule's
  findings are accepted: by rule order, then chronologically within a rule.
  Later rules can therefore cite earlier findings by their final id.
* Duplicate findings (same rule, same set of supporting events) are dropped
  and counted in ``duplicates_removed``.
* Results are identical for identical inputs. The only value that depends on
  the clock is ``generated_at`` / ``detected_at``; pass ``now`` to fix it.
"""

from __future__ import annotations

import dataclasses
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Optional, Sequence, Union

from security.detection.base import Rule, RuleContext
from security.detection.config import DetectionConfig
from security.detection.rules import default_rules
from security.models.schemas import DetectionResult, Finding, RuleRunSummary, Timeline
from security.timeline import build_case_timeline


def run_detection(
    timeline: Timeline,
    config: Optional[DetectionConfig] = None,
    rules: Optional[Sequence[Rule]] = None,
    rule_ids: Optional[Iterable[str]] = None,
    now: Optional[datetime] = None,
) -> DetectionResult:
    """Run detection rules over ``timeline``.

    Args:
        timeline: the incident timeline (Phase 4).
        config: thresholds/indicators; defaults to ``DetectionConfig()``.
        rules: custom rule instances; defaults to the built-in rules.
        rule_ids: run only these rule ids (order of ``rules`` is kept).
        now: analysis time (timezone-aware); defaults to the current UTC time.

    Raises:
        TypeError / ValueError: invalid arguments (wrong types, naive ``now``,
            duplicate or unknown rule ids, a rule that returns another rule's id).
    """
    if not isinstance(timeline, Timeline):
        raise TypeError(f"timeline must be a Timeline, got {type(timeline).__name__}")
    if config is None:
        config = DetectionConfig()
    elif not isinstance(config, DetectionConfig):
        raise TypeError(f"config must be a DetectionConfig, got {type(config).__name__}")
    if now is None:
        now = datetime.now(timezone.utc)
    elif not isinstance(now, datetime) or now.tzinfo is None:
        raise ValueError("now must be a timezone-aware datetime")

    selected = list(rules) if rules is not None else default_rules(config)
    for rule in selected:
        if not isinstance(rule, Rule):
            raise TypeError(f"rules must be Rule instances, got {type(rule).__name__}")
    ids = [rule.rule_id for rule in selected]
    duplicated = sorted({i for i in ids if ids.count(i) > 1})
    if duplicated:
        raise ValueError(f"duplicate rule id(s): {', '.join(duplicated)}")
    if rule_ids is not None:
        wanted = list(rule_ids)
        unknown = sorted(set(wanted) - set(ids))
        if unknown:
            raise ValueError(f"unknown rule id(s) {unknown}; available: {', '.join(ids)}")
        selected = [rule for rule in selected if rule.rule_id in set(wanted)]

    events = [entry.to_event() for entry in timeline.entries]
    accepted: list[Finding] = []
    summaries: list[RuleRunSummary] = []
    rules_run: list[str] = []
    seen: set[tuple] = set()
    duplicates = 0

    for rule in selected:
        output = rule.evaluate(RuleContext(
            events=events, now=now, case_id=timeline.case_id,
            prior_findings=list(accepted), rules_run=list(rules_run)))
        kept = 0
        for finding in output.findings:
            if finding.rule_id != rule.rule_id:
                raise ValueError(
                    f"rule {rule.rule_id} returned a finding for {finding.rule_id}")
            signature = (finding.rule_id, tuple(sorted(finding.supporting_events)))
            if signature in seen:
                duplicates += 1
                continue
            seen.add(signature)
            accepted.append(dataclasses.replace(
                finding, finding_id=f"F-{len(accepted) + 1:03d}"))
            kept += 1
        rules_run.append(rule.rule_id)
        summaries.append(RuleRunSummary(
            rule.rule_id, rule.name, output.events_considered, kept,
            list(output.data_gaps)))

    return DetectionResult(
        case_id=timeline.case_id, generated_at=now, event_count=timeline.event_count,
        config=config.to_dict(), rules=summaries, findings=accepted,
        duplicates_removed=duplicates)


def detect_case(
    folder: Union[str, Path],
    config: Optional[DetectionConfig] = None,
    rule_ids: Optional[Iterable[str]] = None,
    now: Optional[datetime] = None,
) -> DetectionResult:
    """Validate, normalize, build the timeline and run detection on a folder.

    Raises:
        EvidenceNotValidError: the evidence failed validation.
    """
    return run_detection(build_case_timeline(folder), config=config,
                         rule_ids=rule_ids, now=now)
