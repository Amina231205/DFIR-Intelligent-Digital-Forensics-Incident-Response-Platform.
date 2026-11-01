"""Tests for the v2 minimized AI input and grounded output contract."""

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
from security.ai.contract import AI_CONTRACT_VERSION
from security.investigation import investigate_case


SAMPLE = Path(__file__).parents[1] / "security" / "sample_evidence" / "INC-001"
NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


@pytest.fixture
def ai_context():
    result = investigate_case(SAMPLE, now=NOW)
    return result, adapt_investigation(result)


def _valid_response(payload):
    fact = payload["fact_catalog"][0]
    return {
        "contract_version": AI_CONTRACT_VERSION,
        "incident_ref": payload["incident_ref"],
        "source_schema_version": payload["source_schema_version"],
        "confirmed_fact_ids": [fact["fact_id"]],
        "observations": [{
            "observation_id": "OBS-001",
            "statement": "The cited records are associated with a deterministic finding.",
            "verification_status": "unverified",
            "confidence": {
                "level": "low",
                "justification": "This generated statement requires analyst review.",
            },
            "supporting_evidence": deepcopy(fact["supporting_evidence"]),
        }],
        "hypotheses": [],
        "recommendations": [],
    }


def _validate(payload, output, result):
    return validate_ai_output(payload, output, source_result=result)


def test_adapter_is_minimized_detached_and_uses_fact_catalogue(ai_context):
    result, payload = ai_context
    before = result.to_dict()
    assert payload["contract_version"] == "2.0"
    assert payload["incident_ref"] != result.incident_id
    assert payload["device_ref"] != result.device
    assert payload["timeline"]
    assert payload["findings"]
    assert payload["iocs"]
    assert payload["mitre_mappings"]
    assert payload["fact_catalog"]
    assert "details" not in payload["timeline"][0]
    assert "timestamp" not in payload["timeline"][0]
    assert "value" not in payload["iocs"][0]
    assert set(payload["findings"][0]) == {
        "finding_id", "rule_id", "severity", "confidence", "supporting_events",
        "evidence_sources", "ioc_ids", "attack_ids",
    }
    validate_ai_input(payload, source_result=result)
    payload["timeline"].clear()
    assert result.to_dict() == before


def test_valid_response_resolves_facts_from_local_catalogue(ai_context):
    result, payload = ai_context
    output = _valid_response(payload)
    analysis = _validate(payload, output, result)
    assert analysis["confirmed_facts"] == [payload["fact_catalog"][0]]
    assert analysis["confirmed_facts"][0]["verification_status"] == "source_recorded"
    assert analysis["observations"][0]["verification_status"] == "unverified"


def test_confidence_justification_uses_parent_references(ai_context):
    result, payload = ai_context
    output = _valid_response(payload)
    observation = output["observations"][0]
    finding_id = observation["supporting_evidence"]["finding_ids"][0]
    observation["confidence"]["justification"] = f"Source finding {finding_id} is cited."
    _validate(payload, output, result)

    unrelated_finding_id = next(
        finding["finding_id"] for finding in payload["findings"]
        if finding["finding_id"] != finding_id
        and finding["finding_id"] not in observation["supporting_evidence"]["finding_ids"]
    )
    observation["confidence"]["justification"] = (
        f"Unrelated finding {unrelated_finding_id} supports this conclusion."
    )
    with pytest.raises(AIContractValidationError, match="uncited identifier"):
        _validate(payload, output, result)

    output = _valid_response(payload)
    output["observations"][0]["confidence"]["justification"] = (
        "The source shows 203.0.113.99 contacted hostile.example.test."
    )
    with pytest.raises(AIContractValidationError, match="unsupported indicator"):
        _validate(payload, output, result)

    output = _valid_response(payload)
    output["hypotheses"] = [{
        "hypothesis_id": "HYP-001",
        "statement": "The sequence may merit review.",
        "verification_status": "unverified",
        "confidence": {
            "level": "low",
            "justification": "The event occurred at 2030-01-02T03:04:05Z.",
        },
        "supporting_evidence": deepcopy(payload["fact_catalog"][0]["supporting_evidence"]),
    }]
    with pytest.raises(AIContractValidationError, match="unsupported timestamp"):
        _validate(payload, output, result)


def test_rejects_missing_or_empty_support(ai_context):
    result, payload = ai_context
    output = _valid_response(payload)
    output["observations"][0]["supporting_evidence"] = {
        "finding_ids": [], "event_ids": [], "ioc_ids": [], "attack_ids": [],
        "evidence_refs": [],
    }
    with pytest.raises(AIContractValidationError, match="at least one finding or event"):
        _validate(payload, output, result)


def test_rejects_unknown_fact_and_entity_ids(ai_context):
    result, payload = ai_context
    output = _valid_response(payload)
    output["confirmed_fact_ids"] = ["FACT-999"]
    with pytest.raises(AIContractValidationError, match="unknown IDs"):
        _validate(payload, output, result)

    output = _valid_response(payload)
    output["observations"][0]["supporting_evidence"]["event_ids"] = ["E-99999"]
    with pytest.raises(AIContractValidationError, match="unknown IDs"):
        _validate(payload, output, result)


def test_rejects_unrelated_finding_ioc_pair(ai_context):
    result, payload = ai_context
    output = _valid_response(payload)
    support = output["observations"][0]["supporting_evidence"]
    finding_id = support["finding_ids"][0]
    unrelated = next(
        ioc["ioc_id"] for ioc in payload["iocs"]
        if finding_id not in ioc["related_findings"]
    )
    support["ioc_ids"] = [unrelated]
    with pytest.raises(AIContractValidationError, match="unrelated finding"):
        _validate(payload, output, result)


def test_rejects_evidence_record_not_linked_to_cited_event(ai_context):
    result, payload = ai_context
    output = _valid_response(payload)
    ref = output["observations"][0]["supporting_evidence"]["evidence_refs"][0]
    ref["evidence_id"] = "EVL-9999"
    with pytest.raises(AIContractValidationError, match="not associated with event"):
        _validate(payload, output, result)


def test_rejects_unknown_evidence_file_pair(ai_context):
    result, payload = ai_context
    output = _valid_response(payload)
    ref = output["observations"][0]["supporting_evidence"]["evidence_refs"][0]
    ref["evidence_file"] = "not-a-source.json"
    with pytest.raises(AIContractValidationError, match="not associated"):
        _validate(payload, output, result)


def test_rejects_claims_with_invented_ioc_attack_or_timestamp(ai_context):
    result, payload = ai_context
    output = _valid_response(payload)
    output["observations"][0]["statement"] = "Traffic used 203.0.113.250."
    with pytest.raises(AIContractValidationError, match="unsupported indicator"):
        _validate(payload, output, result)

    output = _valid_response(payload)
    output["observations"][0]["statement"] = "The host contacted beacon.attacker.test."
    with pytest.raises(AIContractValidationError, match="unsupported indicator"):
        _validate(payload, output, result)

    output = _valid_response(payload)
    output["observations"][0]["statement"] = r"The file was C:\Users\Public\payload.ps1."
    with pytest.raises(AIContractValidationError, match="unsupported indicator"):
        _validate(payload, output, result)

    output = _valid_response(payload)
    output["observations"][0]["statement"] = "This matches T9999."
    with pytest.raises(AIContractValidationError, match="unsupported ATT&CK"):
        _validate(payload, output, result)

    output = _valid_response(payload)
    output["observations"][0]["statement"] = "The event occurred at 2026-10-08T07:31:03Z."
    with pytest.raises(AIContractValidationError, match="unsupported timestamp"):
        _validate(payload, output, result)

    output = _valid_response(payload)
    output["observations"][0]["statement"] = "The activity happened on October 9, 2026."
    with pytest.raises(AIContractValidationError, match="unsupported timestamp"):
        _validate(payload, output, result)


def test_allows_existing_ioc_and_timestamp_only_with_matching_references(ai_context):
    result, payload = ai_context
    output = _valid_response(payload)
    support = output["observations"][0]["supporting_evidence"]
    cited_ioc = next(
        ioc for ioc in result.iocs
        if ioc.ioc_id in support["ioc_ids"] and ioc.type.value == "ip"
    )
    output["observations"][0]["statement"] = f"The cited indicator is {cited_ioc.value}."
    _validate(payload, output, result)

    output = _valid_response(payload)
    support = output["observations"][0]["supporting_evidence"]
    cited_event_id = support["event_ids"][0]
    cited_event = next(event for event in result.timeline if event.event_id == cited_event_id)
    timestamp = cited_event.timestamp.isoformat().replace("+00:00", "Z")
    output["observations"][0]["statement"] = f"The cited event is recorded at {timestamp}."
    _validate(payload, output, result)


def test_rejects_invalid_verification_status_and_uncited_ids(ai_context):
    result, payload = ai_context
    output = _valid_response(payload)
    output["observations"][0]["verification_status"] = "confirmed"
    with pytest.raises(AIContractValidationError, match="must be 'unverified'"):
        _validate(payload, output, result)

    output = _valid_response(payload)
    output["observations"][0]["statement"] += " Finding F-999 is related."
    with pytest.raises(AIContractValidationError, match="uncited identifier"):
        _validate(payload, output, result)


def test_output_cannot_add_security_authoritative_collections(ai_context):
    result, payload = ai_context
    output = _valid_response(payload)
    output["findings"] = [{"finding_id": "F-999", "rule_id": "DET-999"}]
    with pytest.raises(AIContractValidationError, match="unsupported fields"):
        _validate(payload, output, result)


def test_confirmed_facts_cannot_be_rewritten_or_added(ai_context):
    result, payload = ai_context
    output = _valid_response(payload)
    output["confirmed_facts"] = [{
        "fact_id": payload["fact_catalog"][0]["fact_id"],
        "statement": "The model authored this confirmed statement.",
    }]
    with pytest.raises(AIContractValidationError, match="unsupported fields"):
        _validate(payload, output, result)

    output = _valid_response(payload)
    payload["fact_catalog"][0]["statement"] = "A rewritten source fact."
    with pytest.raises(AIContractValidationError, match="does not match its deterministic finding"):
        _validate(payload, output, result)


def test_recommendation_requires_analyst_review_and_evidence(ai_context):
    result, payload = ai_context
    output = _valid_response(payload)
    output["recommendations"] = [{
        "recommendation_id": "REC-001",
        "action": "Review the cited record with the system owner.",
        "classification": "suggestion",
        "status": "analyst_review",
        "supporting_evidence": deepcopy(payload["fact_catalog"][0]["supporting_evidence"]),
    }]
    assert _validate(payload, output, result)["recommendations"] == output["recommendations"]
    output["recommendations"][0]["status"] = "automatic_response"
    with pytest.raises(AIContractValidationError, match="must be 'analyst_review'"):
        _validate(payload, output, result)

    output = _valid_response(payload)
    output["recommendations"] = [{
        "recommendation_id": "REC-002",
        "action": "Review the cited record.",
        "classification": "suggestion",
        "status": "analyst_review",
        "supporting_evidence": {
            "finding_ids": [], "event_ids": [], "ioc_ids": [], "attack_ids": [],
            "evidence_refs": [],
        },
    }]
    with pytest.raises(AIContractValidationError, match="at least one finding or event"):
        _validate(payload, output, result)

    output = _valid_response(payload)
    output["recommendations"] = [{
        "recommendation_id": "REC-003",
        "action": "Run an automatic remediation.",
        "classification": "action",
        "status": "analyst_review",
        "supporting_evidence": deepcopy(payload["fact_catalog"][0]["supporting_evidence"]),
    }]
    with pytest.raises(AIContractValidationError, match="classification must be 'suggestion'"):
        _validate(payload, output, result)


def test_relationships_are_checked_without_a_finding_citation(ai_context):
    result, payload = ai_context
    output = _valid_response(payload)
    support = output["observations"][0]["supporting_evidence"]
    support["finding_ids"] = []
    event_record = next(
        event["evidence_id"] for event in payload["timeline"]
        if event["event_id"] == support["event_ids"][0]
    )
    unrelated_ioc = next(
        ioc for ioc in payload["iocs"]
        if event_record not in {ref["evidence_id"] for ref in ioc["evidence_refs"]}
    )
    support["ioc_ids"] = [unrelated_ioc["ioc_id"]]
    with pytest.raises(AIContractValidationError, match="unrelated event .* and IOC"):
        _validate(payload, output, result)


def test_empty_investigation_context_accepts_only_neutral_output():
    result = investigate_case(SAMPLE, now=NOW)
    result.findings = []
    result.iocs = []
    result.mitre_mappings = []
    result.timeline = []
    from security.ai import adapt_investigation

    payload = adapt_investigation(result)
    output = {
        "contract_version": "2.0",
        "incident_ref": payload["incident_ref"],
        "source_schema_version": payload["source_schema_version"],
        "confirmed_fact_ids": [],
        "observations": [],
        "hypotheses": [],
        "recommendations": [],
    }
    assert _validate(payload, output, result)["confirmed_facts"] == []


def test_confidence_and_ai_output_do_not_change_security_findings(ai_context):
    result, payload = ai_context
    before = result.to_dict()
    output = _valid_response(payload)
    analysis = _validate(payload, output, result)
    assert analysis["observations"][0]["confidence"]["level"] == "low"
    assert result.to_dict() == before
