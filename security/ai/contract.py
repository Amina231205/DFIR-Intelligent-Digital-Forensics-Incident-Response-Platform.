"""Typed contracts for minimized AI context and separate AI analysis output."""

from __future__ import annotations

from typing import Literal, TypedDict

AI_CONTRACT_VERSION = "2.0"
AI_CONFIDENCE_LEVELS = ("low", "medium", "high")
AI_BASE_LIMITATIONS = (
    "Source recorded facts describe supplied evidence and are not proof of malicious activity.",
    "AI-authored claims are unverified interpretations and require analyst review.",
)


class EvidenceReference(TypedDict, total=False):
    evidence_id: str
    evidence_file: str
    related_finding_ids: list[str]
    related_event_ids: list[str]
    related_ioc_ids: list[str]


class SupportingEvidence(TypedDict):
    finding_ids: list[str]
    event_ids: list[str]
    ioc_ids: list[str]
    attack_ids: list[str]
    evidence_refs: list[EvidenceReference]


class AIConfidence(TypedDict):
    level: Literal["low", "medium", "high"]
    justification: str


class AIEvent(TypedDict):
    event_id: str
    sequence: int
    event_type: str
    actor_ref: str | None
    evidence_id: str
    evidence_file: str


class AIFinding(TypedDict):
    finding_id: str
    rule_id: str
    severity: str
    confidence: str
    supporting_events: list[str]
    evidence_sources: list[str]
    ioc_ids: list[str]
    attack_ids: list[str]


class AIIoc(TypedDict):
    ioc_id: str
    type: str
    related_findings: list[str]
    evidence_refs: list[EvidenceReference]


class AIMapping(TypedDict):
    mapping_id: str
    technique_id: str
    related_findings: list[str]
    supporting_events: list[str]
    evidence_sources: list[str]
    ioc_ids: list[str]


class AIFact(TypedDict):
    fact_id: str
    statement: str
    verification_status: Literal["source_recorded"]
    supporting_evidence: SupportingEvidence


class AIInput(TypedDict):
    """Allowlisted analysis context; intentionally excludes raw evidence text."""

    contract_version: str
    incident_ref: str
    source_schema_version: str
    device_ref: str
    timeline: list[AIEvent]
    findings: list[AIFinding]
    iocs: list[AIIoc]
    mitre_mappings: list[AIMapping]
    fact_catalog: list[AIFact]


class AIObservation(TypedDict):
    observation_id: str
    statement: str
    verification_status: Literal["unverified"]
    confidence: AIConfidence
    supporting_evidence: SupportingEvidence


class AIHypothesis(TypedDict):
    hypothesis_id: str
    statement: str
    verification_status: Literal["unverified"]
    confidence: AIConfidence
    supporting_evidence: SupportingEvidence


class AIRecommendation(TypedDict):
    recommendation_id: str
    action: str
    classification: Literal["suggestion"]
    status: Literal["analyst_review"]
    supporting_evidence: SupportingEvidence


class AIOutput(TypedDict):
    """Untrusted v2 response before application-generated facts are materialized."""

    contract_version: str
    incident_ref: str
    source_schema_version: str
    confirmed_fact_ids: list[str]
    observations: list[AIObservation]
    hypotheses: list[AIHypothesis]
    recommendations: list[AIRecommendation]


class AIAnalysis(TypedDict):
    """Validated AI result kept separate from deterministic investigation data."""

    contract_version: str
    incident_ref: str
    source_schema_version: str
    confirmed_facts: list[AIFact]
    observations: list[AIObservation]
    hypotheses: list[AIHypothesis]
    recommendations: list[AIRecommendation]
    limitations: list[str]
