"""Phase 7 integration tests for ATT&CK mapping and its command-line interface."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from helpers import SAMPLE_DIR
from security.mitre import map_case
from security.mitre.__main__ import main as mitre_cli

NOW = "2026-10-19T00:00:00Z"
NOW_DT = datetime(2026, 10, 19, tzinfo=timezone.utc)
EXPECTED_TECHNIQUES = {
    "T1059.001", "T1136.001", "T1098.007", "T1027.010", "T1110.001", "T1105"
}


def test_sample_case_maps_expected_techniques_and_findings():
    result = map_case(SAMPLE_DIR, now=NOW_DT)

    assert result.case_id == "INC-001"
    assert {mapping.technique_id for mapping in result.mappings} == EXPECTED_TECHNIQUES
    assert len(result.mappings) == 6
    assert len(result.findings) == 4
    assert len(result.evaluations) == 11
    assert result.data_gaps == []
    assert all(mapping.related_findings for mapping in result.mappings)
    assert all(mapping.reason and mapping.confidence for mapping in result.mappings)
    assert all(f.mitre_techniques for f in result.findings)


def test_mapper_output_is_deterministic_for_fixed_analysis_time():
    first = map_case(SAMPLE_DIR, now=NOW_DT)
    second = map_case(SAMPLE_DIR, now=NOW_DT)

    assert first.to_dict() == second.to_dict()
    assert all(isinstance(item, str) for finding in first.findings
               for item in finding.mitre_techniques)


def test_cli_json_outputs_documented_result(capsys):
    exit_code = mitre_cli([str(SAMPLE_DIR), "--now", NOW, "--json"])
    captured = capsys.readouterr()

    assert exit_code == 0
    output = json.loads(captured.out)
    assert output["case_id"] == "INC-001"
    assert {item["technique_id"] for item in output["mappings"]} == EXPECTED_TECHNIQUES
    assert len(output["findings"]) == 4
    assert captured.err == ""


def test_cli_list_is_available_without_evidence_folder(capsys):
    exit_code = mitre_cli(["--list"])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "Supported mappings:" in captured.out
    assert "Confidence scale:" in captured.out
    assert "T1059.001" in captured.out
    assert captured.err == ""


def test_cli_requires_folder_or_list(capsys):
    exit_code = mitre_cli([])
    captured = capsys.readouterr()

    assert exit_code == 2
    assert "an evidence folder is required" in captured.err
