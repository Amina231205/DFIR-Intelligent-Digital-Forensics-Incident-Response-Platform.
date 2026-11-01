"""Focused tests for the Phase 1 AI input/output contract."""

from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path

import pytest

from security.ai import (
    AIContractValidationError,
    adapt_investigation,
    validate_ai_input,
    validate_ai_output,
)
from security.ai.contract import AI_CONTRACT_VERSION, NEUTRAL_EMPTY_SUMMARY
from security.investigation import investigate_case


SAMPLE = Path(__file__).parents[1] / "security" / "sample_evidence" / "INC-001"
NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


@pytest.fixture
def ai_input():
    result = investigate_case(SAMPLE, now=NOW)
    return result, adapt_investigation(result)


def _valid_output(ai_input):
    result = ai_input["security_result"]
    finding = next(item for item in result["findings"] if item["finding_id"] == "F-001")
    event_id = finding["supporting_events"][0]
    event = next(item for item in result["timeline"] if item["event_id"] == event_id)
    ioc_id = finding["iocs"][0]
    ioc = next(item for item in result["iocs"] if item["ioc_id"] == ioc_id)
    attack_id = finding["mitre_techniques"][0]
    mapping = next(item for item in result["mitre_mappings"]
                   if item["technique_id"] == attack_id)
    record_id = event["evidence_id"]
    return {
        "contract_version": AI_CONTRACT_VERSION,
        "incident_id": result["incident_id"],
        "source_schema_version": result["schema_version"],
        "executive_summary": "A rule-based finding records the cited logon activity for analyst review.",
        "executive_summary_basis": {"observation_ids": ["OBS-001"], "hypothesis_ids": []},
        "observations": [{
            "observation_id": "OBS-001",
            "statement": "The finding includes a cited logon event.",
            "supporting_evidence": {
                "finding_ids": [finding["finding_id"]],
                "event_ids": [event_id],
                "ioc_ids": [ioc_id],
                "attack_ids": [attack_id],
                "evidence_refs": [{
                    "evidence_id": record_id,
                    "related_finding_ids": [finding["finding_id"]],
                    "related_event_ids": [event_id],
                    "related_ioc_ids": [ioc_id],
                }],
            },
        }],
        "hypotheses": [],
        "limitations": [],
        "recommended_next_steps": ["Review the cited records with the system owner."],
    }, ioc, mapping


def test_adapter_uses_real_schema_and_does_not_mutate(ai_input):
    result, payload = ai_input
    before = result.to_dict()
    assert payload["contract_version"] == "1.0"
    assert set(payload["security_result"]) == set(before)
    assert payload["security_result"]["finding_links"][0] == {
        "finding_id": "F-001",
        "event_ids": result.finding_links[0]["event_ids"],
        "evidence_record_ids": result.finding_links[0]["evidence_record_ids"],
        "ioc_ids": result.finding_links[0]["ioc_ids"],
        "mitre_technique_ids": result.finding_links[0]["mitre_technique_ids"],
    }
    assert set(payload["security_result"]["finding_assessments"][0]["observed_facts"]) == {
        "rule_id", "rule_name", "supporting_event_ids", "evidence_record_ids",
        "matched_indicators", "description",
    }
    assert payload["security_result"]["findings"][0]["mitre_techniques"]
    assert payload["security_result"]["mitre_mappings"]
    payload["security_result"]["findings"][0]["supporting_events"].clear()
    assert result.to_dict() == before


def test_valid_output_checks_finding_event_ioc_and_attack_associations(ai_input):
    _, payload = ai_input
    output, _, _ = _valid_output(payload)
    validate_ai_input(payload)
    validate_ai_output(payload, output)


def test_rejects_record_id_attached_to_wrong_event(ai_input):
    _, payload = ai_input
    output, _, _ = _valid_output(payload)
    ref = output["observations"][0]["supporting_evidence"]["evidence_refs"][0]
    ref["related_finding_ids"] = []
    ref["related_ioc_ids"] = []
    ref["evidence_id"] = "EVL-0001" if ref["evidence_id"] != "EVL-0001" else "EVL-0002"
    with pytest.raises(AIContractValidationError, match="not associated with event"):
        validate_ai_output(payload, output)


def test_rejects_unpaired_evidence_file_association(ai_input):
    _, payload = ai_input
    output, _, _ = _valid_output(payload)
    ref = output["observations"][0]["supporting_evidence"]["evidence_refs"][0]
    ref["evidence_file"] = "made-up.json"
    with pytest.raises(AIContractValidationError, match="not directly associated"):
        validate_ai_output(payload, output)


def test_accepts_explicit_record_file_pair_from_occurrence(ai_input):
    _, payload = ai_input
    output, ioc, _ = _valid_output(payload)
    matching = next((occ for occ in ioc["occurrences"]
                     if occ["evidence_id"] == output["observations"][0]["supporting_evidence"]["evidence_refs"][0]["evidence_id"]), None)
    if matching is None:
        pytest.skip("selected event record is not one of this IOC's occurrences")
    output["observations"][0]["supporting_evidence"]["evidence_refs"][0]["evidence_file"] = matching["evidence_file"]
    validate_ai_output(payload, output)


def test_rejects_unknown_and_unrelated_ids(ai_input):
    _, payload = ai_input
    output, _, _ = _valid_output(payload)
    support = output["observations"][0]["supporting_evidence"]
    support["event_ids"] = ["E-DOES-NOT-EXIST"]
    with pytest.raises(AIContractValidationError, match="unknown IDs"):
        validate_ai_output(payload, output)

    output, _, _ = _valid_output(payload)
    output["observations"][0]["supporting_evidence"]["attack_ids"] = ["T9999"]
    with pytest.raises(AIContractValidationError, match="unknown IDs"):
        validate_ai_output(payload, output)


def test_rejects_existing_but_unrelated_finding_ioc_pair(ai_input):
    _, payload = ai_input
    output, _, _ = _valid_output(payload)
    support = output["observations"][0]["supporting_evidence"]
    finding_id = support["finding_ids"][0]
    unrelated_ioc = next(
        item["ioc_id"] for item in payload["security_result"]["iocs"]
        if finding_id not in item.get("related_findings", [])
    )
    support["ioc_ids"] = [unrelated_ioc]
    support["evidence_refs"] = []
    with pytest.raises(AIContractValidationError, match="unrelated finding"):
        validate_ai_output(payload, output)


def test_zero_hypotheses_and_empty_security_collections_are_supported():
    payload = {
        "contract_version": AI_CONTRACT_VERSION,
        "security_result": {
            "incident_id": "EMPTY-001",
            "schema_version": "1.0",
            "evidence_integrity": [],
            "findings": [], "timeline": [], "iocs": [], "mitre_mappings": [],
        },
    }
    validate_ai_input(payload)
    output = {
        "contract_version": AI_CONTRACT_VERSION,
        "incident_id": "EMPTY-001",
        "source_schema_version": "1.0",
        "executive_summary": NEUTRAL_EMPTY_SUMMARY,
        "executive_summary_basis": {"observation_ids": [], "hypothesis_ids": []},
        "observations": [], "hypotheses": [],
        "limitations": ["No timeline events or Security findings were provided."],
        "recommended_next_steps": [],
    }
    validate_ai_output(payload, output)


def test_empty_analysis_requires_limitations_and_neutral_summary():
    payload = {"contract_version": AI_CONTRACT_VERSION,
               "security_result": {"incident_id": "EMPTY-002"}}
    output = {
        "contract_version": AI_CONTRACT_VERSION,
        "incident_id": "EMPTY-002", "source_schema_version": "",
        "executive_summary": "No attack occurred.",
        "executive_summary_basis": {"observation_ids": [], "hypothesis_ids": []},
        "observations": [], "hypotheses": [], "limitations": [],
        "recommended_next_steps": [],
    }
    with pytest.raises(AIContractValidationError, match="neutral executive summary"):
        validate_ai_output(payload, output)
    output["executive_summary"] = NEUTRAL_EMPTY_SUMMARY
    with pytest.raises(AIContractValidationError, match="explicit limitations"):
        validate_ai_output(payload, output)


def test_hypothesis_requires_ai_confidence_and_grounded_summary(ai_input):
    _, payload = ai_input
    output, _, _ = _valid_output(payload)
    output["hypotheses"] = [{
        "hypothesis_id": "HYP-001",
        "statement": "The activity may have been unauthorized.",
        "supporting_evidence": output["observations"][0]["supporting_evidence"],
        "confidence": {"level": "medium", "justification": "Based on the cited rule result only."},
    }]
    output["executive_summary_basis"]["hypothesis_ids"] = ["HYP-001"]
    validate_ai_output(payload, output)
    output["hypotheses"][0]["confidence"].pop("justification")
    with pytest.raises(AIContractValidationError, match="justification"):
        validate_ai_output(payload, output)


def test_summary_basis_must_reference_existing_statements(ai_input):
    _, payload = ai_input
    output, _, _ = _valid_output(payload)
    output["executive_summary_basis"]["observation_ids"] = ["OBS-MISSING"]
    with pytest.raises(AIContractValidationError, match="unknown statement IDs"):
        validate_ai_output(payload, output)


def test_ai_confidence_is_not_written_into_security_result(ai_input):
    result, payload = ai_input
    before = deepcopy(payload["security_result"])
    output, _, _ = _valid_output(payload)
    output["hypotheses"] = [{
        "hypothesis_id": "HYP-001", "statement": "Possible hypothesis.",
        "supporting_evidence": output["observations"][0]["supporting_evidence"],
        "confidence": {"level": "low", "justification": "Limited information."},
    }]
    output["executive_summary_basis"]["hypothesis_ids"] = ["HYP-001"]
    validate_ai_output(payload, output)
    assert payload["security_result"] == before
    assert result.findings[0].confidence.value != output["hypotheses"][0]["confidence"]["level"]

