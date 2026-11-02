"""CLI integration tests for the mock-only AI-assisted investigation path."""

import socket
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path

import pytest

from security.ai import (
    AIContractValidationError,
    AIProviderError,
    adapt_investigation,
    validate_ai_output,
)
from security.ai.contract import AI_CONTRACT_VERSION
from security.ai.report import format_ai_report
from security.ai.service import AIServiceResult
from security.investigation import investigate_case, investigation_to_json
from security.investigation import __main__ as investigation_cli


SAMPLE = Path(__file__).parents[1] / "security" / "sample_evidence" / "INC-001"
NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _fixed_result():
    return investigate_case(SAMPLE, now=NOW)


def test_mock_cli_separates_labeled_ai_report_from_unchanged_json(monkeypatch, capsys):
    result = _fixed_result()
    before = result.to_dict()
    monkeypatch.setattr(investigation_cli, "investigate_case", lambda _: result)

    exit_code = investigation_cli.main([str(SAMPLE), "--ai-provider", "mock"])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert captured.out == investigation_to_json(result) + "\n"
    assert captured.err.startswith("MOCK/DEMO — NOT REAL LLM ANALYSIS\n")
    for section in ("Confirmed Facts:", "Observations:", "Hypotheses:", "Recommendations:"):
        assert section in captured.err
    assert "The deterministic analysis produced finding" in captured.err
    assert result.to_dict() == before


def test_default_cli_output_remains_compatible_and_does_not_call_ai(monkeypatch, capsys):
    result = _fixed_result()
    monkeypatch.setattr(investigation_cli, "investigate_case", lambda _: result)

    def unexpected_ai_call(*args, **kwargs):
        raise AssertionError("AI service must not run by default")

    monkeypatch.setattr(investigation_cli, "analyze_investigation", unexpected_ai_call)
    exit_code = investigation_cli.main([str(SAMPLE)])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert captured.out == investigation_to_json(result) + "\n"
    assert captured.err == ""


def test_output_file_contains_only_deterministic_json_and_ai_stays_on_stderr(
    monkeypatch, capsys, tmp_path
):
    result = _fixed_result()
    monkeypatch.setattr(investigation_cli, "investigate_case", lambda _: result)
    output_path = tmp_path / "investigation.json"

    exit_code = investigation_cli.main([
        str(SAMPLE), "--output", str(output_path), "--ai-provider", "mock",
    ])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert output_path.read_text(encoding="utf-8") == investigation_to_json(result) + "\n"
    assert captured.out == ""
    assert captured.err.startswith("MOCK/DEMO — NOT REAL LLM ANALYSIS\n")


def test_empty_fact_catalogue_renders_all_sections_as_empty(monkeypatch, capsys):
    result = _fixed_result()
    result.findings = []
    result.iocs = []
    result.mitre_mappings = []
    result.timeline = []
    monkeypatch.setattr(investigation_cli, "investigate_case", lambda _: result)

    exit_code = investigation_cli.main([str(SAMPLE), "--ai-provider", "mock"])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "Confirmed Facts:\n  (none)" in captured.err
    assert "Observations:\n  (none)" in captured.err
    assert "Hypotheses:\n  (none)" in captured.err
    assert "Recommendations:\n  (none)" in captured.err


def test_invalid_evidence_has_sanitized_ai_mode_error(tmp_path, capsys):
    sensitive_path = tmp_path / "PRIVATE-CASE-SENTINEL"
    with pytest.raises(SystemExit) as exc_info:
        investigation_cli.main([str(sensitive_path), "--ai-provider", "mock"])
    captured = capsys.readouterr()

    assert exc_info.value.code == 2
    assert "Evidence validation failed" in captured.err
    assert "PRIVATE-CASE-SENTINEL" not in captured.err
    assert captured.out == ""


def test_invalid_ai_response_is_reported_safely_after_json(monkeypatch, capsys):
    result = _fixed_result()
    monkeypatch.setattr(investigation_cli, "investigate_case", lambda _: result)

    def invalid_ai(*args, **kwargs):
        raise AIContractValidationError("PRIVATE-RESPONSE-SENTINEL")

    monkeypatch.setattr(investigation_cli, "analyze_investigation", invalid_ai)
    exit_code = investigation_cli.main([str(SAMPLE), "--ai-provider", "mock"])
    captured = capsys.readouterr()

    assert exit_code == 3
    assert captured.out == investigation_to_json(result) + "\n"
    assert "AI response was rejected" in captured.err
    assert "PRIVATE-RESPONSE-SENTINEL" not in captured.err
    assert "Confirmed Facts:" not in captured.err


def test_provider_failure_does_not_print_chained_exception_details(monkeypatch, capsys):
    result = _fixed_result()
    monkeypatch.setattr(investigation_cli, "investigate_case", lambda _: result)

    def provider_failure(*args, **kwargs):
        try:
            raise RuntimeError("PRIVATE-CHAINED-SENTINEL")
        except RuntimeError as cause:
            raise AIProviderError("sensitive provider detail") from cause

    monkeypatch.setattr(investigation_cli, "analyze_investigation", provider_failure)
    exit_code = investigation_cli.main([str(SAMPLE), "--ai-provider", "mock"])
    captured = capsys.readouterr()

    assert exit_code == 3
    assert captured.out == investigation_to_json(result) + "\n"
    assert "AI analysis failed" in captured.err
    assert "PRIVATE-CHAINED-SENTINEL" not in captured.err
    assert "sensitive provider detail" not in captured.err


def test_ai_report_does_not_expose_sensitive_source_values(monkeypatch, capsys):
    result = _fixed_result()
    sentinel = "PRIVATE-USER-HOST-COMMAND-IOC-SENTINEL"
    result.device = sentinel
    result.incident_id = sentinel
    result.users_involved = [sentinel]
    for event in result.timeline:
        event.user = sentinel
        event.details["command_line"] = sentinel
    for ioc in result.iocs:
        ioc.value = sentinel
    monkeypatch.setattr(investigation_cli, "investigate_case", lambda _: result)

    exit_code = investigation_cli.main([str(SAMPLE), "--ai-provider", "mock"])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert sentinel not in captured.err
    assert "MOCK/DEMO — NOT REAL LLM ANALYSIS" in captured.err
    assert result.to_dict()["device"] == sentinel


def test_mock_cli_makes_no_network_calls(monkeypatch, capsys):
    result = _fixed_result()
    monkeypatch.setattr(investigation_cli, "investigate_case", lambda _: result)

    def reject_network(*args, **kwargs):
        raise AssertionError("Mock Provider must not use the network")

    monkeypatch.setattr(socket, "create_connection", reject_network)
    monkeypatch.setattr(socket.socket, "connect", reject_network)

    exit_code = investigation_cli.main([str(SAMPLE), "--ai-provider", "mock"])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "MOCK/DEMO — NOT REAL LLM ANALYSIS" in captured.err


def test_invalid_provider_choice_is_rejected_by_argparse(monkeypatch, capsys):
    def investigation_must_not_run(_):
        raise AssertionError("invalid provider must fail before investigation")

    monkeypatch.setattr(investigation_cli, "investigate_case", investigation_must_not_run)

    with pytest.raises(SystemExit) as exc_info:
        investigation_cli.main([str(SAMPLE), "--ai-provider", "openai"])
    captured = capsys.readouterr()

    assert exc_info.value.code == 2
    assert "invalid choice" in captured.err


def test_report_formatter_displays_claim_status_confidence_and_references():
    result = _fixed_result()
    ai_input = adapt_investigation(result)
    fact = ai_input["fact_catalog"][0]
    supporting_evidence = fact["supporting_evidence"]
    provider_output = {
        "contract_version": AI_CONTRACT_VERSION,
        "incident_ref": ai_input["incident_ref"],
        "source_schema_version": ai_input["source_schema_version"],
        "confirmed_fact_ids": [fact["fact_id"]],
        "observations": [{
            "observation_id": "OBS-001",
            "statement": "The cited events occur in the supplied timeline.",
            "verification_status": "unverified",
            "confidence": {
                "level": "medium",
                "justification": "This interpretation needs analyst review.",
            },
            "supporting_evidence": deepcopy(supporting_evidence),
        }],
        "hypotheses": [{
            "hypothesis_id": "HYP-001",
            "statement": "The sequence may warrant further review.",
            "verification_status": "unverified",
            "confidence": {
                "level": "low",
                "justification": "This is an unverified possibility.",
            },
            "supporting_evidence": deepcopy(supporting_evidence),
        }],
        "recommendations": [{
            "recommendation_id": "REC-001",
            "action": "Review the cited finding with the system owner.",
            "classification": "suggestion",
            "status": "analyst_review",
            "supporting_evidence": deepcopy(supporting_evidence),
        }],
    }
    analysis = validate_ai_output(ai_input, provider_output, source_result=result)
    ai_result: AIServiceResult = {
        "provider_id": "mock",
        "mode": "MOCK/DEMO",
        "analysis": analysis,
    }
    report = format_ai_report(ai_result)

    expected_finding = supporting_evidence["finding_ids"][0]
    expected_event = supporting_evidence["event_ids"][0]
    expected_evidence = supporting_evidence["evidence_refs"][0]["evidence_id"]

    assert report.startswith("MOCK/DEMO — NOT REAL LLM ANALYSIS")
    assert "The cited events occur in the supplied timeline." in report
    assert "The sequence may warrant further review." in report
    assert "Review the cited finding with the system owner." in report
    assert f"Findings: {expected_finding}" in report
    assert f"Events: {expected_event}" in report
    assert f"Evidence: {expected_evidence}" in report
    assert "Confidence: medium — This interpretation needs analyst review." in report
    assert "Confidence: low — This is an unverified possibility." in report
    assert "Status: unverified" in report
    assert "Status: analyst_review (suggestion)" in report
