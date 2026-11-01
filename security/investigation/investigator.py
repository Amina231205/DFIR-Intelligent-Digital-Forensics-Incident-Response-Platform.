"""Phase 8 deterministic investigation assembly.

This module orchestrates the public analysis stages and produces a single,
traceable InvestigationResult. It does not make a malware verdict or perform
response actions. Analysis is read-only.
"""
from __future__ import annotations

import hashlib
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional, Union

from security.models.schemas import (
    EvidenceSource, InvestigationResult, Severity, to_plain,
)
from security.validation.validator import EvidenceNotValidError, validate_and_load
from security.normalization.normalizer import normalize_validated
from security.timeline.timeline import build_timeline_from_result
from security.detection.engine import run_detection
from security.ioc.extractor import extract_iocs
from security.mitre.mapper import map_findings


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc).isoformat()
        return value.astimezone(timezone.utc).isoformat()
    if isinstance(value, str):
        return value
    return None


def _next_steps(finding: Any) -> list[str]:
    """Return conservative review steps grounded in the fired rule and evidence."""
    rid = str(getattr(finding, "rule_id", "")).lower()
    steps = [
        "Review the cited evidence records and confirm the activity with the system owner.",
        "Preserve the original evidence package and its manifest before making changes.",
    ]
    if "brute" in rid or "logon" in rid:
        steps.append("Correlate the cited logon events with the account, source host, and approved access activity.")
    elif "powershell" in rid or "ps" in rid:
        steps.append("Review the cited PowerShell command and its parent process in context; do not execute the command.")
    elif "account" in rid or "creation" in rid:
        steps.append("Verify whether the cited account creation was authorized and review its privileges and subsequent activity.")
    else:
        steps.append("Correlate the cited events with adjacent timeline activity before assigning incident impact.")
    sev = getattr(getattr(finding, "severity", None), "value", str(getattr(finding, "severity", ""))).lower()
    if sev in {"high", "critical"}:
        steps.append("Prioritize analyst review because the rule assigned a high severity; treat this as triage priority, not proof of compromise.")
    return steps


def investigate_case(
    folder: Union[str, Path],
    *,
    detection_config: Any = None,
    ioc_config: Any = None,
    now: Optional[datetime] = None,
) -> InvestigationResult:
    """Validate once, analyze the validated bytes, and assemble a case result.

    Raises EvidenceNotValidError when evidence fails validation. ``now`` may be
    supplied for deterministic tests; it must be timezone-aware.
    """
    if now is not None and (now.tzinfo is None or now.utcoffset() is None):
        raise ValueError("now must be timezone-aware")
    generated_at = now.astimezone(timezone.utc) if now else _utc_now()
    validation, loaded = validate_and_load(folder)
    if not validation.valid:
        raise EvidenceNotValidError(validation)

    evidence = {
        source: loaded[f"{source.value}.json"].data
        for source in EvidenceSource
        if f"{source.value}.json" in loaded and loaded[f"{source.value}.json"].data is not None
    }
    if not evidence:
        raise EvidenceNotValidError(validation)
    normalized = normalize_validated(evidence, validation)
    timeline = build_timeline_from_result(normalized)
    detection = run_detection(timeline, config=detection_config, now=generated_at)
    ioc_result = extract_iocs(timeline, detection, ioc_config)
    mapped = map_findings(detection, ioc_result, timeline)

    raw_ids: set[str] = set()
    for envelope in evidence.values():
        for record in envelope.get("records", []):
            if isinstance(record, dict) and isinstance(record.get("record_id"), str):
                raw_ids.add(record["record_id"])
    event_ids = {entry.event_id for entry in timeline.entries}
    finding_ids = {finding.finding_id for finding in mapped.findings}
    ioc_ids = {ioc.ioc_id for ioc in ioc_result.iocs}

    provenance_issues: list[dict[str, str]] = []
    links: list[dict[str, Any]] = []
    assessments: list[dict[str, Any]] = []
    for finding in mapped.findings:
        missing_events = sorted(set(finding.supporting_events) - event_ids)
        missing_records = sorted(set(finding.evidence_sources) - raw_ids)
        missing_iocs = sorted(set(finding.iocs) - ioc_ids)
        if missing_events or missing_records or missing_iocs:
            provenance_issues.append({
                "finding_id": finding.finding_id,
                "missing_event_ids": ", ".join(missing_events),
                "missing_record_ids": ", ".join(missing_records),
                "missing_ioc_ids": ", ".join(missing_iocs),
            })
        links.append({
            "finding_id": finding.finding_id,
            "event_ids": sorted(set(finding.supporting_events)),
            "evidence_record_ids": sorted(set(finding.evidence_sources)),
            "ioc_ids": sorted(set(finding.iocs)),
            "mitre_technique_ids": sorted(set(finding.mitre_techniques)),
        })
        assessments.append({
            "finding_id": finding.finding_id,
            "observed_facts": {
                "rule_id": finding.rule_id,
                "rule_name": finding.rule_name,
                "supporting_event_ids": sorted(set(finding.supporting_events)),
                "evidence_record_ids": sorted(set(finding.evidence_sources)),
                "matched_indicators": to_plain(finding.matched_indicators),
                "description": finding.description,
            },
            "inference": {
                "assessment": "Rule conditions matched; analyst review is required. This is not proof of malicious activity.",
                "severity": finding.severity.value,
                "confidence": finding.confidence.value,
                "mitre_technique_ids": sorted(set(finding.mitre_techniques)),
            },
            "recommended_next_steps": _next_steps(finding),
        })
        finding.recommended_next_steps = _next_steps(finding)

    data_gaps: set[str] = set()
    data_gaps.update(str(item) for item in ioc_result.data_gaps)
    data_gaps.update(str(item) for item in mapped.data_gaps)
    data_gaps.update(issue.message for issue in validation.warnings)
    data_gaps.update(warning.message for warning in normalized.warnings)

    # Flag duplicate normalized observations without deleting either record.
    signatures: Counter[tuple[Any, ...]] = Counter()
    for entry in timeline.entries:
        signature = (
            entry.timestamp.isoformat(), entry.event_type.value, entry.source.value,
            entry.device, entry.user, json.dumps(entry.details, sort_keys=True, default=str),
        )
        signatures[signature] += 1
    duplicate_count = sum(count - 1 for count in signatures.values() if count > 1)
    if duplicate_count:
        data_gaps.add(
            f"{duplicate_count} duplicate-looking timeline observation(s) were detected by matching timestamp, type, host, user, and details; records were retained for analyst review."
        )

    # Timestamps later than their source envelope's collection time are suspicious
    # data-quality conditions, not silently corrected.
    for entry in timeline.entries:
        envelope = evidence.get(entry.source)
        collected = _iso(envelope.get("collected_at")) if envelope else None
        event_time = entry.timestamp.astimezone(timezone.utc)
        if collected:
            try:
                parsed = datetime.fromisoformat(collected.replace("Z", "+00:00"))
                if parsed.tzinfo is not None and event_time > parsed.astimezone(timezone.utc):
                    data_gaps.add(
                        f"{entry.evidence_file}:{entry.evidence_id} timestamp is later than the source envelope collected_at value."
                    )
            except ValueError:
                pass

    integrity = []
    for name, item in sorted(loaded.items()):
        integrity.append({
            "file": name,
            "sha256": item.sha256,
            "size_bytes": item.size_bytes,
            "read_and_hashed_during_validation": item.sha256 is not None,
        })

    timestamps = [entry.timestamp for entry in timeline.entries]
    host = normalized.host
    device = normalized.device or str(host.get("hostname", "unknown"))
    summary = (
        f"Analysis of case {normalized.case_id} on {device}: "
        f"{len(timeline.entries)} timeline event(s), {len(mapped.findings)} finding(s), "
        f"{len(ioc_result.iocs)} IOC(s), and {len(mapped.mappings)} supported ATT&CK mapping(s). "
        "Findings are rule-based triage results and require analyst review."
    )
    return InvestigationResult(
        incident_id=normalized.case_id,
        device=device,
        generated_at=generated_at,
        time_start=min(timestamps) if timestamps else None,
        time_end=max(timestamps) if timestamps else None,
        users_involved=sorted({entry.user for entry in timeline.entries if entry.user}),
        evidence_files=integrity,
        timeline=[entry.to_event() for entry in timeline.entries],
        findings=mapped.findings,
        iocs=ioc_result.iocs,
        mitre_mappings=mapped.mappings,
        summary=summary,
        finding_assessments=assessments,
        finding_links=links,
        data_gaps=sorted(data_gaps),
        provenance_check={
            "status": "passed" if not provenance_issues else "failed",
            "findings_checked": len(mapped.findings),
            "issues": provenance_issues,
            "raw_record_count": len(raw_ids),
            "timeline_event_count": len(event_ids),
            "ioc_count": len(ioc_ids),
            "note": "Reference consistency only; does not establish that evidence is authentic or that activity is malicious.",
        },
    )


def investigation_to_json(result: InvestigationResult, *, indent: int = 2) -> str:
    """Serialize an investigation result as stable, JSON-safe text."""
    return json.dumps(to_plain(result), indent=indent, sort_keys=True, ensure_ascii=False)
