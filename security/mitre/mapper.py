"""ATT&CK mapping engine (Module 6) - evaluates mapping rules on findings.

    from security.mitre import map_case
    result = map_case("security/sample_evidence/INC-001")
    for mapping in result.mappings:
        print(mapping.mapping_id, mapping.technique_id, mapping.tactic,
              mapping.confidence.value, mapping.related_findings)

The engine contains NO ATT&CK knowledge and NO per-technique logic. It loads a
``MappingCatalog`` (dataset + declarative mapping rules), and for every
finding applies the rules defined for the finding's detection rule. A rule
maps only when its conditions hold on the finding's recorded evidence
(matched indicators, context, related IOCs). Otherwise the outcome is recorded
as ``not_mapped`` (conditions evaluated, do not hold) or ``not_evaluable``
(needed data missing); nothing is forced.

Mappings are aggregated per (technique, tactic): one mapping lists every
finding that supports it, with per-finding detail in ``sources``. Mapping
confidence is the best confidence among its sources.

The inputs are never modified: findings are returned as copies with
``mitre_techniques`` filled in. No clock and no network are used.
"""

from __future__ import annotations

import copy
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional, Union

from security.detection import DetectionConfig, run_detection
from security.ioc import IocConfig, extract_iocs
from security.mitre import conditions
from security.mitre.catalog import MappingCatalog, MappingRule, load_catalog
from security.models.schemas import (
    DetectionResult, Finding, IocResult, IOC, MappingEvaluation, MitreMapping, MitreResult,
    Timeline)
from security.timeline import build_case_timeline

_LEVEL = {"Low": 0, "Medium": 1, "High": 2}


def _natural(identifier: str) -> tuple[str, int]:
    """Sort key so 'E-00009' < 'E-00010' and 'F-2' < 'F-10'."""
    match = re.match(r"^(.*?)(\d+)$", identifier)
    return (match.group(1), int(match.group(2))) if match else (identifier, -1)


@dataclass
class _Source:
    """One finding's support for one mapping."""

    order: int
    finding_id: str
    rule_id: str
    mapping_rule_id: str
    level: str
    factors: list[str]
    rationale: str
    events: list[str]
    records: list[str]
    ioc_ids: list[str]

    def as_dict(self) -> dict[str, Any]:
        return {"finding_id": self.finding_id, "rule_id": self.rule_id,
                "mapping_rule_id": self.mapping_rule_id, "confidence": self.level,
                "rationale": self.rationale, "supporting_events": self.events,
                "evidence_sources": self.records, "ioc_ids": self.ioc_ids,
                "confidence_factors": self.factors}


def _confidence(rule: MappingRule, subject: conditions.Subject) -> tuple[str, list[str]]:
    """Mapping confidence for one finding: base, optional raise, capped by the finding."""
    spec = rule.confidence
    level, factors = spec.base, [f"base level for this mapping: {spec.base}"]
    if spec.raised:
        value, why = conditions.evaluate(spec.raise_when, subject)
        if value is True:
            level = spec.raised
            factors.append(f"raised to {level}: {spec.raise_reason}")
        elif value is None:
            factors.append("not raised: the corroboration condition could not be evaluated "
                           f"({why})")
        else:
            factors.append(f"not raised: it is not the case that {spec.raise_reason}")
    cap = subject.finding.confidence.value
    if _LEVEL[level] > _LEVEL[cap]:
        level = cap
        factors.append(f"capped at the finding's confidence ({cap})")
    return level, factors


def _record_index(finding: Finding, timeline: Optional[Timeline]) -> dict[str, str]:
    """event id -> raw record id, from the finding itself and (preferred) the timeline."""
    index: dict[str, str] = {}
    if len(finding.evidence_sources) >= len(finding.supporting_events):
        index.update(zip(finding.supporting_events, finding.evidence_sources))
    for match in finding.matched_indicators:
        if isinstance(match, dict) and match.get("event_id") and match.get("evidence_id"):
            index.setdefault(match["event_id"], match["evidence_id"])
    for key in ("correlated_records", "creating_evidence"):
        records = finding.context.get(key, [])
        for record in records if isinstance(records, list) else []:
            if isinstance(record, dict) and record.get("event_id") and record.get("evidence_id"):
                index.setdefault(record["event_id"], record["evidence_id"])
    if timeline is not None:
        index.update({e.event_id: e.evidence_id for e in timeline.entries})
    return index


def map_findings(
    detection: DetectionResult,
    iocs: Optional[IocResult] = None,
    timeline: Optional[Timeline] = None,
    catalog: Optional[MappingCatalog] = None,
) -> MitreResult:
    """Map the findings of ``detection`` to ATT&CK techniques and tactics.

    Args:
        detection: findings from the detection stage.
        iocs: optional IOC result for the same detection; adds IOC ids and
            enables conditions that need IOC evidence (without it those
            conditions are "not evaluable", never silently false).
        timeline: optional; when given, event references are verified.
        catalog: dataset + mapping definitions; defaults to the packaged ones.

    Raises:
        TypeError / ValueError: wrong argument types, inputs from different
            cases, an IOC result that does not belong to ``detection``, or
            duplicate finding ids.
    """
    if not isinstance(detection, DetectionResult):
        raise TypeError(f"detection must be a DetectionResult, got {type(detection).__name__}")
    if iocs is not None and not isinstance(iocs, IocResult):
        raise TypeError(f"iocs must be an IocResult, got {type(iocs).__name__}")
    if timeline is not None and not isinstance(timeline, Timeline):
        raise TypeError(f"timeline must be a Timeline, got {type(timeline).__name__}")
    if catalog is not None and not isinstance(catalog, MappingCatalog):
        raise TypeError(f"catalog must be a MappingCatalog, got {type(catalog).__name__}")
    catalog = catalog or load_catalog()

    cases = {c for c in (detection.case_id, getattr(iocs, "case_id", None),
                         getattr(timeline, "case_id", None)) if c}
    if len(cases) > 1:
        raise ValueError(f"inputs belong to different cases: {sorted(cases)}")

    ids = [f.finding_id for f in detection.findings]
    duplicated = sorted({i for i in ids if ids.count(i) > 1})
    if duplicated:
        raise ValueError(f"duplicate finding id(s): {', '.join(duplicated)}")
    findings = list(detection.findings)
    if iocs is not None:
        if [f.finding_id for f in iocs.findings] != ids:
            raise ValueError("the IOC result was not produced from this detection result "
                             "(its finding ids differ)")
        findings = list(iocs.findings)            # same findings, with their iocs filled in

    gaps: set[str] = set()
    related: dict[str, list[IOC]] = {i: [] for i in ids}
    if iocs is None:
        gaps.add("no IOC result was provided: IOC ids are not recorded and conditions that "
                 "need IOC evidence cannot be evaluated")
    else:
        known_iocs = {i.ioc_id for i in iocs.iocs}
        for ioc in iocs.iocs:
            for finding_id in ioc.related_findings:
                if finding_id in related:
                    related[finding_id].append(ioc)
                else:
                    gaps.add(f"{ioc.ioc_id} relates to finding {finding_id}, which is not "
                             "in the detection result")
        for finding in findings:
            for ioc_id in finding.iocs:
                if ioc_id not in known_iocs:
                    gaps.add(f"{finding.finding_id} lists IOC {ioc_id}, which is not in the "
                             "IOC result")
    timeline_ids = {e.event_id for e in timeline.entries} if timeline is not None else None
    if timeline_ids is not None:
        for finding in findings:
            for event_id in finding.supporting_events:
                if event_id not in timeline_ids:
                    gaps.add(f"{finding.finding_id} cites event {event_id}, which is not in "
                             "the timeline")
        if iocs is not None:
            for ioc in iocs.iocs:
                for occurrence in ioc.occurrences:
                    if occurrence.get("event_id") not in timeline_ids:
                        gaps.add(f"{ioc.ioc_id} has an occurrence in event "
                                 f"{occurrence.get('event_id')}, which is not in the timeline")

    evaluations: list[MappingEvaluation] = []
    sources: dict[tuple[str, str], list[_Source]] = {}
    seen: dict[tuple[str, str, str], str] = {}

    for order, finding in enumerate(findings):
        fid, detection_rule = finding.finding_id, finding.rule_id
        if not (isinstance(finding.context, dict)
                and isinstance(finding.matched_indicators, list)):
            gaps.add(f"{fid} has a malformed context or matched_indicators; it was not evaluated")
            evaluations.append(MappingEvaluation(
                fid, detection_rule, None, None, "not_evaluable",
                "the finding's context or matched indicators are malformed"))
            continue
        rules = catalog.rules_for(detection_rule)
        if not rules:
            evaluations.append(MappingEvaluation(
                fid, detection_rule, None, None, "no_rules",
                f"no mapping rules are defined for {detection_rule}"))
            continue
        subject = conditions.Subject(finding, related[fid] if iocs is not None else None)
        records = _record_index(finding, timeline)
        for rule in rules:
            value, why = conditions.evaluate(rule.conditions, subject)
            if value is not True:
                evaluations.append(MappingEvaluation(
                    fid, detection_rule, rule.id, rule.technique_id,
                    "not_mapped" if value is False else "not_evaluable", why))
                continue
            key = (rule.technique_id, rule.tactic_id)
            if (fid, *key) in seen:
                evaluations.append(MappingEvaluation(
                    fid, detection_rule, rule.id, rule.technique_id, "duplicate",
                    f"already mapped for this finding by rule {seen[(fid, *key)]}"))
                continue
            seen[(fid, *key)] = rule.id

            events = conditions.collect_event_ids(rule.evidence, subject)
            if timeline_ids is not None:
                missing = [e for e in events if e not in timeline_ids]
                for event_id in missing:
                    gaps.add(f"{fid}: mapping rule {rule.id} cites event {event_id}, which is "
                             "not in the timeline; it was left out")
                events = [e for e in events if e in timeline_ids]
            events = sorted(events, key=_natural)
            level, factors = _confidence(rule, subject)
            chosen = conditions.select_iocs(rule.iocs, subject)
            sources.setdefault(key, []).append(_Source(
                order, fid, detection_rule, rule.id, level, factors,
                conditions.render_rationale(rule.rationale, subject), events,
                sorted({records[e] for e in events if e in records}, key=_natural),
                sorted({i.ioc_id for i in chosen}, key=_natural)))
            evaluations.append(MappingEvaluation(
                fid, detection_rule, rule.id, rule.technique_id, "mapped", why))

    mappings = [_build_mapping(catalog, key, contributions)
                for key, contributions in sorted(
                    sources.items(), key=lambda item: (item[0][1], item[0][0]))]
    mapped_by_finding: dict[str, set[str]] = {}
    for mapping in mappings:
        for finding_id in mapping.related_findings:
            mapped_by_finding.setdefault(finding_id, set()).add(mapping.technique_id)
    result_findings = []
    for finding in findings:
        updated = copy.deepcopy(finding)
        updated.mitre_techniques = sorted(mapped_by_finding.get(finding.finding_id, ()))
        result_findings.append(updated)

    return MitreResult(
        case_id=detection.case_id or getattr(iocs, "case_id", None)
        or getattr(timeline, "case_id", None),
        dataset=dict(catalog.dataset.metadata),
        mapping_definition={
            "version": catalog.definition["version"],
            "reviewed_against": catalog.definition["reviewed_against"],
            "rule_count": len(catalog.rules),
            "supported_techniques": catalog.supported_technique_ids(),
            "confidence_scale": dict(catalog.confidence_scale)},
        mappings=mappings, findings=result_findings, evaluations=evaluations,
        data_gaps=sorted(gaps))


def _build_mapping(catalog: MappingCatalog, key: tuple[str, str],
                   contributions: list[_Source]) -> MitreMapping:
    technique_id, tactic_id = key
    dataset = catalog.dataset
    technique, tactic = dataset.techniques[technique_id], dataset.tactics[tactic_id]
    best = min(contributions, key=lambda c: (-_LEVEL[c.level], c.order))
    parent = dataset.techniques[technique.parent_id] if technique.parent_id else None
    factors = list(best.factors)
    reason = best.rationale
    others = [c.finding_id for c in contributions if c is not best]
    if others:
        factors.append(f"also supported by {', '.join(others)}; the best confidence among "
                       "the supporting findings is reported")
        reason += (f" (Shown for {best.finding_id}; also supported by "
                   f"{', '.join(others)}, see sources.)")
    return MitreMapping(
        technique_id=technique_id,
        technique_name=dataset.display_name(technique_id),
        tactic=tactic.name,
        related_finding=contributions[0].finding_id,
        reason=reason,
        mapping_id=f"MAP-{technique_id}-{tactic_id}",
        tactic_id=tactic_id,
        tactics=[{"id": t, "name": dataset.tactics[t].name} for t in technique.tactic_ids],
        is_subtechnique=technique.is_subtechnique,
        parent_technique_id=parent.id if parent else None,
        parent_technique_name=parent.name if parent else None,
        subtechnique_id=technique_id if parent else None,
        subtechnique_name=technique.name if parent else None,
        related_findings=sorted({c.finding_id for c in contributions}, key=_natural),
        supporting_events=sorted({e for c in contributions for e in c.events}, key=_natural),
        evidence_sources=sorted({r for c in contributions for r in c.records}, key=_natural),
        ioc_ids=sorted({i for c in contributions for i in c.ioc_ids}, key=_natural),
        confidence=best.level,
        confidence_factors=factors,
        sources=[c.as_dict() for c in contributions],
        attack_version=str(dataset.metadata["attack_version"]),
    )


def map_case(
    folder: Union[str, Path],
    detection_config: Optional[DetectionConfig] = None,
    ioc_config: Optional[IocConfig] = None,
    now: Any = None,
    catalog: Optional[MappingCatalog] = None,
) -> MitreResult:
    """Validate, normalize, build the timeline, detect, extract IOCs and map a folder.

    Raises:
        EvidenceNotValidError: the evidence failed validation.
    """
    timeline = build_case_timeline(folder)
    detection = run_detection(timeline, config=detection_config, now=now)
    iocs = extract_iocs(timeline, detection, ioc_config)
    return map_findings(detection, iocs, timeline, catalog)
