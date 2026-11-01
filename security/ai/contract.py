"""Names and typing contracts for the isolated Sentinel AI boundary."""

from __future__ import annotations

from typing import Literal, TypedDict

AI_CONTRACT_VERSION = "1.0"
AI_CONFIDENCE_LEVELS = ("low", "medium", "high")
NEUTRAL_EMPTY_SUMMARY = "The available InvestigationResult did not support a grounded AI assessment."


class SecurityInput(TypedDict, total=False):
    """Serialized Security InvestigationResult fields.

    The fields mirror security.models.schemas.InvestigationResult. Collection
    fields are optional here so older/partial serialized payloads can be read
    as empty collections by the adapter and validator.
    """

    incident_id: str
    device: str
    generated_at: str
    schema_version: str
    time_start: str | None
    time_end: str | None
    users_involved: list[str]
    evidence_files: list[dict[str, object]]
    timeline: list[dict[str, object]]
    findings: list[dict[str, object]]
    iocs: list[dict[str, object]]
    mitre_mappings: list[dict[str, object]]
    summary: str
    finding_assessments: list[dict[str, object]]
    finding_links: list[dict[str, object]]
    data_gaps: list[str]
    provenance_check: dict[str, object]
    evidence_integrity: list[dict[str, object]]


class AIInput(TypedDict):
    contract_version: str
    security_result: SecurityInput


class SupportingEvidence(TypedDict):
    finding_ids: list[str]
    event_ids: list[str]
    ioc_ids: list[str]
    attack_ids: list[str]
    evidence_refs: list[dict[str, object]]


class AIConfidence(TypedDict):
    level: Literal["low", "medium", "high"]
    justification: str


class AIHypothesis(TypedDict):
    hypothesis_id: str
    statement: str
    supporting_evidence: SupportingEvidence
    confidence: AIConfidence


class AIObservation(TypedDict):
    observation_id: str
    statement: str
    supporting_evidence: SupportingEvidence


class AIAnalysis(TypedDict):
    """AI-authored analysis kept separate from Security findings."""

    contract_version: str
    incident_id: str
    source_schema_version: str
    executive_summary: str
    executive_summary_basis: dict[str, list[str]]
    observations: list[AIObservation]
    hypotheses: list[AIHypothesis]
    limitations: list[str]
    recommended_next_steps: list[str]

