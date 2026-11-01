"""Convert an InvestigationResult to an isolated AI input payload."""

from __future__ import annotations

from copy import deepcopy
from typing import Any

from security.ai.contract import AI_CONTRACT_VERSION, AIInput
from security.models.schemas import InvestigationResult, to_plain


def adapt_investigation(result: InvestigationResult) -> AIInput:
    """Return a detached, JSON-safe payload without changing ``result``."""
    if not isinstance(result, InvestigationResult):
        raise TypeError("result must be an InvestigationResult")
    plain = to_plain(result)
    if not isinstance(plain, dict):  # defensive check around the serializer
        raise TypeError("InvestigationResult did not serialize to an object")
    # A deep copy keeps nested mutable dictionaries/lists detached from the
    # Security result. Missing optional collection fields are normalized to [].
    security_result: dict[str, Any] = deepcopy(plain)
    for field in (
        "users_involved", "evidence_files", "timeline", "findings", "iocs",
        "mitre_mappings", "finding_assessments", "finding_links", "data_gaps",
        "evidence_integrity",
    ):
        security_result.setdefault(field, [])
    return {
        "contract_version": AI_CONTRACT_VERSION,
        "security_result": security_result,
    }  # type: ignore[return-value]

