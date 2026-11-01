"""Phase 1 tests: the sample case obeys the Evidence JSON contract.

These are structural checks only. Full validation logic (with clear error
messages) is built and tested in Phase 2.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from security.models.schemas import (
    ENVELOPE_FIELDS,
    MANIFEST_FILENAME,
    RECORD_ID_PREFIX,
    REQUIRED_RECORD_FIELDS,
    REQUIRED_SOURCES,
    SCHEMA_VERSION,
    Confidence,
    EventType,
    EvidenceSource,
    Finding,
    NormalizedEvent,
    Severity,
)
from security.utils.helpers import (
    format_timestamp,
    load_json,
    parse_timestamp,
    sha256_file,
)

CASE_DIR = (
    Path(__file__).resolve().parents[1]
    / "security" / "sample_evidence" / "INC-001"
)
ALL_SOURCES = [s for s in EvidenceSource if (CASE_DIR / f"{s.value}.json").exists()]
TIME_FIELDS = ("timestamp", "boot_time", "created_at", "last_logon", "modified_at")


# ---------------------------------------------------------------- helpers
class TestTimestampHelpers:
    def test_parses_z_suffix_as_utc(self):
        parsed = parse_timestamp("2026-10-08T07:34:01Z")
        assert parsed == datetime(2026, 10, 8, 7, 34, 1, tzinfo=timezone.utc)

    def test_converts_offsets_to_utc(self):
        assert parse_timestamp("2026-10-08T10:34:01+03:00").hour == 7

    @pytest.mark.parametrize("bad", ["2026-10-08T07:34:01", "yesterday", "", 12345])
    def test_rejects_naive_or_invalid(self, bad):
        with pytest.raises(ValueError):
            parse_timestamp(bad)

    def test_round_trip(self):
        text = "2026-10-08T07:34:01Z"
        assert format_timestamp(parse_timestamp(text)) == text


# ------------------------------------------------------ sample case shape
@pytest.mark.parametrize("source", REQUIRED_SOURCES)
def test_required_files_exist(source):
    assert (CASE_DIR / f"{source.value}.json").is_file()


@pytest.mark.parametrize("source", ALL_SOURCES)
class TestEvidenceFile:
    def test_has_envelope(self, source):
        data = load_json(CASE_DIR / f"{source.value}.json")
        for key in ENVELOPE_FIELDS:
            assert key in data, f"{source.value}.json missing '{key}'"
        assert data["schema_version"] == SCHEMA_VERSION
        assert data["source"] == source.value
        assert isinstance(data["records"], list) and data["records"]

    def test_records_have_required_fields(self, source):
        data = load_json(CASE_DIR / f"{source.value}.json")
        for record in data["records"]:
            for key in REQUIRED_RECORD_FIELDS[source]:
                assert key in record, f"{record.get('record_id')} missing '{key}'"

    def test_record_ids_are_prefixed_and_unique(self, source):
        data = load_json(CASE_DIR / f"{source.value}.json")
        ids = [r["record_id"] for r in data["records"]]
        assert len(ids) == len(set(ids))
        assert all(i.startswith(RECORD_ID_PREFIX[source] + "-") for i in ids)

    def test_timestamps_are_valid_utc(self, source):
        data = load_json(CASE_DIR / f"{source.value}.json")
        for record in data["records"]:
            for key in TIME_FIELDS:
                if record.get(key) is not None:
                    parse_timestamp(record[key])  # raises on bad format


def test_case_and_device_consistent_across_files():
    envelopes = [load_json(CASE_DIR / f"{s.value}.json") for s in ALL_SOURCES]
    assert {e["case_id"] for e in envelopes} == {"INC-001"}
    assert {e["device"] for e in envelopes} == {"WIN-PC-01"}


def test_record_ids_unique_across_case():
    ids = [
        r["record_id"]
        for s in ALL_SOURCES
        for r in load_json(CASE_DIR / f"{s.value}.json")["records"]
    ]
    assert len(ids) == len(set(ids))


def test_manifest_hashes_match_files():
    manifest = load_json(CASE_DIR / MANIFEST_FILENAME)
    assert manifest["hash_algorithm"] == "SHA-256"
    assert {f["name"] for f in manifest["files"]} == {
        f"{s.value}.json" for s in ALL_SOURCES
    }
    for entry in manifest["files"]:
        path = CASE_DIR / entry["name"]
        assert sha256_file(path) == entry["sha256"], f"{entry['name']} was modified"
        assert len(load_json(path)["records"]) == entry["record_count"]


def test_sample_contains_no_real_world_indicators():
    """Only reserved documentation IPs/domains are allowed in sample data."""
    text = " ".join(
        (CASE_DIR / f"{s.value}.json").read_text(encoding="utf-8") for s in ALL_SOURCES
    )
    for allowed in ("198.51.100.23", "203.0.113.77", "192.0.2.44", "example.net"):
        assert allowed in text


# ---------------------------------------------------------------- schemas
class TestSchemas:
    def _event(self, **overrides):
        base = dict(
            event_id="E-00001", case_id="INC-001",
            timestamp=datetime(2026, 10, 8, 7, 34, 1, tzinfo=timezone.utc),
            event_type="process_created", source="processes", device="WIN-PC-01",
            user="ahmed", evidence_id="PROC-0006", details={"pid": 6012},
        )
        base.update(overrides)
        return NormalizedEvent(**base)

    def test_normalized_event_serializes_to_json(self):
        event = self._event()
        assert event.event_type is EventType.PROCESS_CREATED
        assert event.evidence_file == "processes.json"
        payload = json.loads(json.dumps(event.to_dict()))
        assert payload["timestamp"] == "2026-10-08T07:34:01Z"
        assert payload["event_type"] == "process_created"

    def test_naive_timestamp_rejected(self):
        with pytest.raises(ValueError):
            self._event(timestamp=datetime(2026, 10, 8, 7, 34, 1))

    def test_unknown_event_type_rejected(self):
        with pytest.raises(ValueError):
            self._event(event_type="made_up_type")

    def test_finding_validates_severity_and_confidence(self):
        finding = Finding(
            finding_id="F-001", rule_id="DET-002", title="Test",
            severity="High", confidence="Medium", device="WIN-PC-01",
            user="ahmed", description="d", reason="r",
            detected_at=datetime(2026, 10, 8, 8, 0, tzinfo=timezone.utc),
        )
        assert finding.severity is Severity.HIGH
        assert finding.confidence is Confidence.MEDIUM
        assert json.loads(json.dumps(finding.to_dict()))["severity"] == "High"
        with pytest.raises(ValueError):
            Finding(
                finding_id="F-002", rule_id="DET-002", title="Bad",
                severity="Scary", confidence="Low", device="x", user=None,
                description="", reason="",
                detected_at=datetime(2026, 10, 8, tzinfo=timezone.utc),
            )
