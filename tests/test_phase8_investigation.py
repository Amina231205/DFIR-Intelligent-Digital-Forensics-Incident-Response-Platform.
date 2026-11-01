from datetime import datetime, timezone
from pathlib import Path

import pytest

from security.investigation import investigate_case, investigation_to_json
from security.validation.validator import EvidenceNotValidError


SAMPLE = Path(__file__).parents[1] / "security" / "sample_evidence" / "INC-001"


def test_investigation_assembles_traceable_result():
    result = investigate_case(SAMPLE, now=datetime(2026, 1, 1, tzinfo=timezone.utc))
    assert result.incident_id == "INC-001"
    assert result.timeline
    assert result.findings
    assert result.summary
    assert result.provenance_check["status"] == "passed"
    assert len(result.finding_assessments) == len(result.findings)
    assert len(result.finding_links) == len(result.findings)
    assert all(f.recommended_next_steps for f in result.findings)
    assert all("not proof" in a["inference"]["assessment"].lower()
               for a in result.finding_assessments)
    assert investigation_to_json(result).startswith("{")
    assert result.evidence_files


def test_investigation_is_deterministic_when_clock_is_fixed():
    fixed = datetime(2026, 1, 1, tzinfo=timezone.utc)
    first = investigate_case(SAMPLE, now=fixed).to_dict()
    second = investigate_case(SAMPLE, now=fixed).to_dict()
    assert first == second


def test_naive_clock_is_rejected():
    with pytest.raises(ValueError, match="timezone-aware"):
        investigate_case(SAMPLE, now=datetime(2026, 1, 1))


def test_invalid_evidence_is_not_analyzed(tmp_path):
    with pytest.raises(EvidenceNotValidError):
        investigate_case(tmp_path)
