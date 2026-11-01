"""Synthetic end-to-end integration checks for the current analysis pipeline.

These tests exercise the checked-in contract fixture only. They do not assert
compatibility with output from the separately maintained Windows collector.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from helpers import edit, rebuild_manifest, snapshot
from security.detection import run_detection
from security.investigation import investigate_case, investigation_to_json
from security.ioc import extract_iocs
from security.mitre import map_findings
from security.normalization import normalize_case
from security.storage import (
    CaseNotFoundError,
    delete_case,
    get_investigation,
    list_cases,
    save_investigation,
)
from security.timeline import build_case_timeline
from security.validation import EvidenceNotValidError, validate_case


FIXED_NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def test_synthetic_case_flows_through_every_analysis_stage(case):
    original_snapshot = snapshot(case)

    validation = validate_case(case)
    assert validation.valid
    assert validation.case_id == "INC-001"

    normalized = normalize_case(case)
    assert normalized.validation is not None and normalized.validation.valid
    assert normalized.case_id == validation.case_id
    assert normalized.events

    timeline = build_case_timeline(case)
    assert timeline.case_id == normalized.case_id
    assert timeline.event_count == len(normalized.events)
    assert [entry.event_id for entry in timeline.entries] == [
        event.event_id for event in normalized.events
    ]
    assert all(
        timeline.get_by_event_id(event.event_id).evidence_id == event.evidence_id
        for event in normalized.events
    )

    detection = run_detection(timeline, now=FIXED_NOW)
    assert detection.case_id == timeline.case_id
    assert detection.event_count == timeline.event_count
    event_ids = {entry.event_id for entry in timeline.entries}
    finding_ids = {finding.finding_id for finding in detection.findings}
    assert detection.findings
    assert all(set(finding.supporting_events) <= event_ids for finding in detection.findings)

    iocs = extract_iocs(timeline, detection)
    assert iocs.case_id == detection.case_id
    assert iocs.iocs
    assert {finding.finding_id for finding in iocs.findings} == finding_ids
    assert all(set(ioc.related_findings) <= finding_ids for ioc in iocs.iocs)
    representative_ioc = next(ioc for ioc in iocs.iocs if ioc.related_findings)
    ioc_finding_id = representative_ioc.related_findings[0]
    ioc_finding = next(finding for finding in iocs.findings
                       if finding.finding_id == ioc_finding_id)
    assert representative_ioc.ioc_id in ioc_finding.iocs

    mapped = map_findings(detection, iocs, timeline)
    assert mapped.case_id == timeline.case_id
    assert mapped.mappings
    assert {finding.finding_id for finding in mapped.findings} == finding_ids
    assert all(set(mapping.related_findings) <= finding_ids for mapping in mapped.mappings)
    representative_mapping = next(
        mapping for mapping in mapped.mappings if mapping.related_findings
    )
    mapping_finding_ids = set(representative_mapping.related_findings)
    mapping_findings = [finding for finding in mapped.findings
                        if finding.finding_id in mapping_finding_ids]
    assert {finding.finding_id for finding in mapping_findings} == mapping_finding_ids
    assert all(
        representative_mapping.technique_id in finding.mitre_techniques
        for finding in mapping_findings
    )
    related_event_ids = {
        event_id for finding in mapping_findings for event_id in finding.supporting_events
    }
    assert set(representative_mapping.supporting_events) <= related_event_ids

    investigation = investigate_case(case, now=FIXED_NOW)
    serialized = json.loads(investigation_to_json(investigation))
    assert investigation.incident_id == mapped.case_id
    assert [event["event_id"] for event in serialized["timeline"]] == [
        entry.event_id for entry in timeline.entries
    ]
    assert {finding["finding_id"] for finding in serialized["findings"]} == finding_ids
    assert {ioc["ioc_id"] for ioc in serialized["iocs"]} == {
        ioc.ioc_id for ioc in iocs.iocs
    }
    assert {mapping["mapping_id"] for mapping in serialized["mitre_mappings"]} == {
        mapping.mapping_id for mapping in mapped.mappings
    }
    assert investigation.provenance_check["status"] == "passed"
    assert snapshot(case) == original_snapshot


def test_contract_permitted_missing_file_and_nullable_value_flow(case):
    # files.json is optional. Remove its manifest entry too, as a producer
    # would when that optional evidence file is not delivered.
    (case / "files.json").unlink()
    rebuild_manifest(case)

    # command_line is required as a key but may be null when unavailable.
    edit(case, "processes.json", lambda data: data["records"][0].update(command_line=None))
    # Also omit an optional record field.
    edit(case, "processes.json", lambda data: data["records"][0].pop("parent_name", None))

    validation = validate_case(case)
    assert validation.valid
    assert {warning.code for warning in validation.warnings} == {"OPTIONAL_FILE_MISSING"}

    normalized = normalize_case(case)
    assert normalized.validation is not None and normalized.validation.valid
    process_event = next(
        event for event in normalized.events if event.evidence_id == "PROC-0001"
    )
    assert process_event.details["command_line"] is None
    assert process_event.details["parent_name"] is None

    investigation = investigate_case(case, now=FIXED_NOW)
    assert investigation.incident_id == "INC-001"
    assert investigation.provenance_check["status"] == "passed"
    assert "files.json" not in {item["file"] for item in investigation.evidence_files}


def test_invalid_evidence_is_rejected_without_repair_or_mutation(case):
    (case / "events.json").write_text("{ invalid JSON", encoding="utf-8")
    before_validation = snapshot(case)

    validation = validate_case(case)
    codes = {issue.code for issue in validation.errors}
    assert not validation.valid
    assert codes == {"JSON_INVALID", "MANIFEST_HASH_MISMATCH"}
    assert snapshot(case) == before_validation

    with pytest.raises(EvidenceNotValidError) as caught:
        investigate_case(case, now=FIXED_NOW)
    assert {issue.code for issue in caught.value.result.errors} == {
        "JSON_INVALID", "MANIFEST_HASH_MISMATCH"
    }
    assert snapshot(case) == before_validation


def test_manifest_detects_changed_evidence_and_validation_leaves_it_untouched(case):
    path = case / "processes.json"
    path.write_bytes(path.read_bytes() + b"\n")
    before_validation = snapshot(case)

    validation = validate_case(case)
    assert not validation.valid
    assert {issue.code for issue in validation.errors} == {"MANIFEST_HASH_MISMATCH"}
    assert snapshot(case) == before_validation

    with pytest.raises(EvidenceNotValidError) as caught:
        investigate_case(case, now=FIXED_NOW)
    assert {issue.code for issue in caught.value.result.errors} == {
        "MANIFEST_HASH_MISMATCH"
    }
    assert snapshot(case) == before_validation


def test_sqlite_persistence_round_trip_and_delete(case, tmp_path):
    result = investigate_case(case, now=FIXED_NOW)
    database = tmp_path / "integration" / "cases.sqlite"

    saved = save_investigation(database, result)
    assert saved["status"] == "created"
    expected = json.loads(investigation_to_json(result))
    assert get_investigation(database, result.incident_id) == expected

    cases = list_cases(database)
    assert len(cases) == 1
    assert cases[0]["case_id"] == result.incident_id
    assert cases[0]["device"] == result.device

    assert delete_case(database, result.incident_id) is True
    assert list_cases(database) == []
    with pytest.raises(CaseNotFoundError):
        get_investigation(database, result.incident_id)
