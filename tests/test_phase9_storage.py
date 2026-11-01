from datetime import datetime, timezone
from pathlib import Path

import pytest

from security.investigation import investigate_case
from security.storage import (
    CaseNotFoundError, StorageValidationError, delete_case, get_investigation,
    list_cases, save_investigation,
)


SAMPLE = Path(__file__).parents[1] / "security" / "sample_evidence" / "INC-001"


@pytest.fixture
def result():
    return investigate_case(SAMPLE, now=datetime(2026, 1, 1, tzinfo=timezone.utc))


def test_save_load_and_idempotency(tmp_path, result):
    db = tmp_path / "cases.sqlite"
    first = save_investigation(db, result)
    second = save_investigation(db, result)
    assert first["status"] == "created"
    assert second["status"] == "unchanged"
    loaded = get_investigation(db, "INC-001")
    assert loaded["incident_id"] == "INC-001"
    assert len(loaded["findings"]) == len(result.findings)
    assert len(loaded["timeline"]) == len(result.timeline)
    assert list_cases(db)[0]["case_id"] == "INC-001"


def test_changed_payload_replaces_case_atomically(tmp_path, result):
    db = tmp_path / "cases.sqlite"
    save_investigation(db, result)
    result.summary += " Updated test summary."
    assert save_investigation(db, result)["status"] == "replaced"
    assert get_investigation(db, "INC-001")["summary"].endswith("Updated test summary.")


def test_case_id_validation(tmp_path, result):
    result.incident_id = "../escape"
    with pytest.raises(StorageValidationError):
        save_investigation(tmp_path / "cases.sqlite", result)


def test_authorization_hook_denies_access(tmp_path, result):
    db = tmp_path / "cases.sqlite"
    with pytest.raises(PermissionError):
        save_investigation(db, result, authorize=lambda action, case_id: False)


def test_missing_case_and_delete(tmp_path, result):
    db = tmp_path / "cases.sqlite"
    with pytest.raises(CaseNotFoundError):
        get_investigation(db, "NO-SUCH-CASE")
    save_investigation(db, result)
    assert delete_case(db, "INC-001") is True
    assert delete_case(db, "INC-001") is False
