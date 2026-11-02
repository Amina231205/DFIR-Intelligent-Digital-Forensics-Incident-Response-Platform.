"""Tests for synchronous AI service orchestration and the local mock."""

from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path

import pytest

from security.ai import (
    AIContractValidationError,
    AIProviderError,
    AIProviderTimeoutError,
    MockProvider,
    analyze_investigation,
)
from security.ai.adapter import adapt_investigation
from security.ai.contract import AI_CONTRACT_VERSION
from security.investigation import investigate_case


SAMPLE = Path(__file__).parents[1] / "security" / "sample_evidence" / "INC-001"
NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _result():
    return investigate_case(SAMPLE, now=NOW)


def test_mock_provider_execution_is_deterministic_and_labeled():
    result = _result()
    before = result.to_dict()
    provider = MockProvider()

    first = analyze_investigation(result, provider)
    second = analyze_investigation(result, provider)

    assert first == second
    assert first["provider_id"] == "mock"
    assert first["mode"] == "MOCK/DEMO"
    assert first["analysis"]["contract_version"] == AI_CONTRACT_VERSION
    assert first["analysis"]["confirmed_facts"] == adapt_investigation(result)["fact_catalog"]
    assert first["analysis"]["observations"] == []
    assert first["analysis"]["hypotheses"] == []
    assert first["analysis"]["recommendations"] == []
    assert result.to_dict() == before


def test_mock_provider_handles_empty_fact_catalogue():
    result = _result()
    result.findings = []
    result.iocs = []
    result.mitre_mappings = []
    result.timeline = []

    outcome = analyze_investigation(result, MockProvider())

    assert outcome["analysis"]["confirmed_facts"] == []
    assert outcome["analysis"]["observations"] == []
    assert outcome["analysis"]["hypotheses"] == []
    assert outcome["analysis"]["recommendations"] == []


class _ResponseProvider:
    provider_id = "test"

    def __init__(self, response):
        self.response = response
        self.calls = 0

    def analyze(self, ai_input):
        self.calls += 1
        return self.response


def test_invalid_provider_output_is_rejected_without_mutating_source():
    result = _result()
    before = result.to_dict()
    provider = _ResponseProvider({"unexpected": "response"})

    with pytest.raises(AIContractValidationError, match="missing fields"):
        analyze_investigation(result, provider)

    assert provider.calls == 1
    assert result.to_dict() == before


@pytest.mark.parametrize("error", [
    AIProviderError("provider unavailable"),
    AIProviderTimeoutError("provider timed out"),
])
def test_typed_provider_errors_are_propagated(error):
    class FailingProvider:
        provider_id = "test"

        def analyze(self, ai_input):
            raise error

    with pytest.raises(type(error), match=str(error)):
        analyze_investigation(_result(), FailingProvider())


def test_unexpected_provider_exception_is_wrapped_with_cause():
    class FailingProvider:
        provider_id = "test"

        def analyze(self, ai_input):
            raise OSError("private internal detail")

    with pytest.raises(AIProviderError, match="AI provider failed") as exc_info:
        analyze_investigation(_result(), FailingProvider())

    assert isinstance(exc_info.value.__cause__, OSError)
    assert "private internal detail" not in str(exc_info.value)


def test_invalid_input_fails_before_provider_invocation(monkeypatch):
    import security.ai.service as service

    result = _result()
    provider = _ResponseProvider({})
    original_adapter = service.adapt_investigation

    def malformed_context(source_result):
        payload = original_adapter(source_result)
        payload["device_ref"] = "PRIVATE-HOST-SENTINEL"
        return payload

    monkeypatch.setattr(service, "adapt_investigation", malformed_context)

    with pytest.raises(AIContractValidationError, match="privacy reference format"):
        service.analyze_investigation(result, provider)

    assert provider.calls == 0


def test_provider_receives_defensive_private_copy_and_source_is_unchanged():
    result = _result()
    before = result.to_dict()
    sentinel = "PRIVATE-SENTINEL-USER-HOST-PATH-IOC"
    result.device = sentinel
    result.incident_id = sentinel
    result.users_involved = [sentinel]
    for event in result.timeline:
        event.user = sentinel
        event.details["command_line"] = sentinel
    for ioc in result.iocs:
        ioc.value = sentinel
    before = result.to_dict()

    class MutatingProvider:
        provider_id = "test"

        def __init__(self):
            self.received = None

        def analyze(self, ai_input):
            self.received = ai_input
            assert sentinel not in repr(ai_input)
            ai_input["timeline"].clear()
            return {
                "contract_version": ai_input["contract_version"],
                "incident_ref": ai_input["incident_ref"],
                "source_schema_version": ai_input["source_schema_version"],
                "confirmed_fact_ids": [],
                "observations": [],
                "hypotheses": [],
                "recommendations": [],
            }

    provider = MutatingProvider()
    outcome = analyze_investigation(result, provider)

    assert provider.received["timeline"] == []
    assert outcome["analysis"]["confirmed_facts"] == []
    assert result.to_dict() == before


def test_phase_one_input_and_output_contracts_remain_unchanged():
    result = _result()
    context = adapt_investigation(result)
    provider = MockProvider()
    raw_output = provider.analyze(deepcopy(context))

    assert set(context) == {
        "contract_version", "incident_ref", "source_schema_version", "device_ref",
        "timeline", "findings", "iocs", "mitre_mappings", "fact_catalog",
    }
    assert set(raw_output) == {
        "contract_version", "incident_ref", "source_schema_version",
        "confirmed_fact_ids", "observations", "hypotheses", "recommendations",
    }
    service_result = analyze_investigation(result, provider)
    assert set(service_result) == {"provider_id", "mode", "analysis"}
