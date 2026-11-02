"""Deterministic, local demonstration provider with no model or network."""

from __future__ import annotations

from security.ai.contract import AIInput, AIOutput


class MockProvider:
    """Select existing deterministic facts and make no authored claims."""

    provider_id = "mock"

    def analyze(self, ai_input: AIInput) -> AIOutput:
        """Return a stable MOCK/DEMO response based only on supplied fact IDs."""
        return {
            "contract_version": ai_input["contract_version"],
            "incident_ref": ai_input["incident_ref"],
            "source_schema_version": ai_input["source_schema_version"],
            "confirmed_fact_ids": [
                fact["fact_id"] for fact in ai_input["fact_catalog"]
            ],
            "observations": [],
            "hypotheses": [],
            "recommendations": [],
        }
