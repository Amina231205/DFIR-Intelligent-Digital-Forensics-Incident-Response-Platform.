"""Build a privacy-minimized AI context from a deterministic investigation."""

from __future__ import annotations

import re
import secrets
import threading
import weakref
from dataclasses import dataclass, field
from typing import Any

from security.ai.contract import AI_CONTRACT_VERSION, AIInput, SupportingEvidence
from security.models.schemas import InvestigationResult


_REFERENCE_TOKEN_LENGTH = 32
CASE_REFERENCE_RE = re.compile(r"^CASE-([0-9a-f]{32})$")
DEVICE_REFERENCE_RE = re.compile(r"^DEVICE-([0-9a-f]{32})$")
ACTOR_REFERENCE_RE = re.compile(r"^ACTOR-([0-9a-f]{32})-([0-9]{3,})$")
_CASE_STATES: dict[int, tuple[weakref.ReferenceType[InvestigationResult], "_CasePrivacyState"]] = {}
_CASE_STATES_LOCK = threading.RLock()


@dataclass
class _CasePrivacyState:
    """Local-only pseudonym map and random case namespace."""

    token: str = field(default_factory=lambda: secrets.token_hex(_REFERENCE_TOKEN_LENGTH // 2))
    actor_refs: dict[str, str] = field(default_factory=dict)


def _forget_case_state(
    identity: int, reference: weakref.ReferenceType[InvestigationResult]
) -> None:
    with _CASE_STATES_LOCK:
        cached = _CASE_STATES.get(identity)
        if cached is not None and cached[0] is reference:
            del _CASE_STATES[identity]


def _case_privacy_state(result: InvestigationResult) -> _CasePrivacyState:
    """Return a random namespace cached only for this result object's lifetime."""
    identity = id(result)
    with _CASE_STATES_LOCK:
        cached = _CASE_STATES.get(identity)
        if cached is not None and cached[0]() is result:
            return cached[1]
        reference = weakref.ref(
            result, lambda ref, key=identity: _forget_case_state(key, ref)
        )
        state = _CasePrivacyState()
        active_tokens = {item[1].token for item in _CASE_STATES.values()}
        while state.token in active_tokens:
            state = _CasePrivacyState()
        _CASE_STATES[identity] = (reference, state)
        return state


def _actor_reference(state: _CasePrivacyState, value: Any) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    key = value.casefold()
    with _CASE_STATES_LOCK:
        if key not in state.actor_refs:
            state.actor_refs[key] = (
                f"ACTOR-{state.token}-{len(state.actor_refs) + 1:03d}"
            )
        return state.actor_refs[key]


def _refs_for_records(
    result: InvestigationResult,
    record_ids: set[str],
    *,
    finding_id: str | None = None,
    event_ids: set[str] | None = None,
    ioc_ids: set[str] | None = None,
) -> list[dict[str, Any]]:
    record_files = {
        event.evidence_id: event.evidence_file
        for event in result.timeline
        if event.evidence_id in record_ids
    }
    refs = []
    for record_id in sorted(record_ids):
        ref: dict[str, Any] = {
            "evidence_id": record_id,
            "related_finding_ids": [],
            "related_event_ids": [],
            "related_ioc_ids": [],
        }
        if record_id in record_files:
            ref["evidence_file"] = record_files[record_id]
        if finding_id:
            ref["related_finding_ids"] = [finding_id]
        if event_ids:
            related_events = [
                event.event_id for event in result.timeline
                if event.evidence_id == record_id and event.event_id in event_ids
            ]
            if related_events:
                ref["related_event_ids"] = related_events
        if ioc_ids:
            related_iocs = [
                ioc.ioc_id for ioc in result.iocs
                if ioc.ioc_id in ioc_ids and (
                    ioc.evidence_id == record_id
                    or any(occurrence.get("evidence_id") == record_id
                           for occurrence in ioc.occurrences)
                )
            ]
            if related_iocs:
                ref["related_ioc_ids"] = sorted(related_iocs)
        refs.append(ref)
    return refs


def _support_for_finding(result: InvestigationResult, finding: Any) -> SupportingEvidence:
    event_ids = set(finding.supporting_events)
    record_ids = set(finding.evidence_sources)
    for event in result.timeline:
        if event.event_id in event_ids:
            record_ids.add(event.evidence_id)
    return {
        "finding_ids": [finding.finding_id],
        "event_ids": sorted(event_ids),
        "ioc_ids": sorted(finding.iocs),
        "attack_ids": sorted(finding.mitre_techniques),
        "evidence_refs": _refs_for_records(
            result,
            record_ids,
            finding_id=finding.finding_id,
            event_ids=event_ids,
            ioc_ids=set(finding.iocs),
        ),
    }


def build_ai_input(result: InvestigationResult) -> AIInput:
    """Return a deterministic allowlist with no raw details or indicator values.

    User values are replaced with per-case ordinal references. Timeline order
    is preserved, while timestamps, event details, device names, command lines,
    file paths, hashes, and literal IOC values are excluded.
    """
    if not isinstance(result, InvestigationResult):
        raise TypeError("result must be an InvestigationResult")

    privacy_state = _case_privacy_state(result)

    events: list[dict[str, Any]] = []
    for sequence, event in enumerate(result.timeline, start=1):
        events.append({
            "event_id": event.event_id,
            "sequence": sequence,
            "event_type": event.event_type.value,
            "actor_ref": _actor_reference(privacy_state, event.user),
            "evidence_id": event.evidence_id,
            "evidence_file": event.evidence_file,
        })

    findings: list[dict[str, Any]] = []
    fact_catalog: list[dict[str, Any]] = []
    for number, finding in enumerate(result.findings, start=1):
        finding_id = finding.finding_id
        findings.append({
            "finding_id": finding_id,
            "rule_id": finding.rule_id,
            "severity": finding.severity.value,
            "confidence": finding.confidence.value,
            "supporting_events": sorted(finding.supporting_events),
            "evidence_sources": sorted(finding.evidence_sources),
            "ioc_ids": sorted(finding.iocs),
            "attack_ids": sorted(finding.mitre_techniques),
        })
        support = _support_for_finding(result, finding)
        if support["event_ids"] or support["evidence_refs"]:
            fact_catalog.append({
                "fact_id": f"FACT-{number:03d}",
                "statement": (
                    f"The deterministic analysis produced finding {finding_id} "
                    f"under rule {finding.rule_id}."
                ),
                "verification_status": "source_recorded",
                "supporting_evidence": support,
            })

    iocs: list[dict[str, Any]] = []
    for ioc in result.iocs:
        occurrence_refs = []
        record_ids = {ioc.evidence_id}
        for occurrence in ioc.occurrences:
            record_id = occurrence.get("evidence_id")
            if isinstance(record_id, str):
                record_ids.add(record_id)
        for record_id in sorted(record_ids):
            ref: dict[str, Any] = {"evidence_id": record_id}
            evidence_file = next(
                (event.evidence_file for event in result.timeline
                 if event.evidence_id == record_id),
                None,
            )
            if evidence_file:
                ref["evidence_file"] = evidence_file
            occurrence_refs.append(ref)
        iocs.append({
            "ioc_id": ioc.ioc_id,
            "type": ioc.type.value,
            "related_findings": sorted(ioc.related_findings),
            "evidence_refs": occurrence_refs,
        })

    mappings = [{
        "mapping_id": mapping.mapping_id,
        "technique_id": mapping.technique_id,
        "related_findings": sorted(mapping.related_findings),
        "supporting_events": sorted(mapping.supporting_events),
        "evidence_sources": sorted(mapping.evidence_sources),
        "ioc_ids": sorted(mapping.ioc_ids),
    } for mapping in result.mitre_mappings]

    return {
        "contract_version": AI_CONTRACT_VERSION,
        "incident_ref": f"CASE-{privacy_state.token}",
        "source_schema_version": result.schema_version,
        "device_ref": f"DEVICE-{privacy_state.token}",
        "timeline": events,
        "findings": findings,
        "iocs": iocs,
        "mitre_mappings": mappings,
        "fact_catalog": fact_catalog,
    }  # type: ignore[return-value]
