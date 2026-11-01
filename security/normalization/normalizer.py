"""Evidence normalization (Module 2) - the public entry point.

    from security.normalization import normalize_case
    result = normalize_case("security/sample_evidence/INC-001")
    for event in result.events:
        print(event.event_id, event.timestamp, event.event_type.value)

Guarantees:

* **Validated input only.** ``normalize_case`` validates the folder and
  analyzes the very bytes that were validated; invalid evidence raises
  ``EvidenceNotValidError`` instead of producing partial output.
* **Read-only.** Nothing on disk is written; input data is never mutated.
* **Deterministic.** Same evidence in, identical output out, regardless of
  the order of records inside the files (see ``event_sort_key``).
* **Traceable.** Every event's ``evidence_id`` is the ``record_id`` of the
  raw record it came from. One record yields exactly one event.
* **users.json = enrichment, system.json = host context.** Neither becomes
  a timeline event.
"""

from __future__ import annotations

import copy
import dataclasses
from pathlib import Path
from typing import Any, Mapping, Optional, Union

from security.models.schemas import (
    EvidenceSource,
    NormalizationResult,
    NormalizationWarning,
    NormalizedEvent,
    ValidationResult,
)
from security.normalization.enrichment import build_user_index, enrich_events
from security.normalization.mappers import MAPPERS, MappingContext
from security.validation import EvidenceNotValidError, validate_and_load

# Same-timestamp events are ordered by source in this fixed order, then by
# the numeric part of the record_id. Users/system rank last (warnings only).
_SOURCE_RANK: dict[EvidenceSource, int] = {
    source: rank for rank, source in enumerate(
        [*MAPPERS, EvidenceSource.USERS, EvidenceSource.SYSTEM])
}


def _record_number(evidence_id: str) -> int:
    """Numeric part of ``PROC-0010`` (numeric, so 0002 sorts before 0010)."""
    try:
        return int(evidence_id.rsplit("-", 1)[1])
    except (IndexError, ValueError):
        return 0


def event_sort_key(event: NormalizedEvent) -> tuple[Any, ...]:
    """Total order used to number events: time, source, record number, id.

    Includes ``evidence_id`` last so two different records can never tie,
    which is what makes the output independent of input record order.
    """
    return (event.timestamp, _SOURCE_RANK[event.source],
            _record_number(event.evidence_id), event.evidence_id)


def _warning_key(warning: NormalizationWarning) -> tuple[Any, ...]:
    return (_SOURCE_RANK[warning.source], _record_number(warning.evidence_id),
            warning.evidence_id, warning.code, warning.message)


def normalize_case(folder: Union[str, Path]) -> NormalizationResult:
    """Validate ``folder`` and normalize it.

    Raises:
        EvidenceNotValidError: the evidence failed validation. The full
            ``ValidationResult`` is on the exception's ``.result``.
    """
    validation, loaded = validate_and_load(folder)
    if not validation.valid:
        raise EvidenceNotValidError(validation)
    evidence = {
        source: loaded[f"{source.value}.json"].data
        for source in EvidenceSource
        if f"{source.value}.json" in loaded
    }
    return normalize_validated(evidence, validation)


def normalize_validated(
    evidence: Mapping[EvidenceSource, Mapping[str, Any]],
    validation: Optional[ValidationResult] = None,
) -> NormalizationResult:
    """Normalize already-validated envelopes (``{source: parsed JSON}``).

    The caller MUST have validated the data (``normalize_case`` does). This
    function trusts the contract and does not re-check it.
    """
    first = next(iter(evidence.values()))
    ctx = MappingContext(case_id=first["case_id"], device=first["device"])

    drafts: list[NormalizedEvent] = []
    source_counts: dict[str, int] = {}
    for source, mapper in MAPPERS.items():
        if source not in evidence:
            continue  # optional file (files.json) was not delivered
        records = evidence[source]["records"]
        source_counts[source.value] = len(records)
        drafts.extend(mapper(record, ctx) for record in records)

    users = [copy.deepcopy(r) for r in
             evidence.get(EvidenceSource.USERS, {}).get("records", [])]
    enrich_events(drafts, build_user_index(users, ctx))

    events = [
        dataclasses.replace(event, event_id=f"E-{number:05d}")
        for number, event in enumerate(sorted(drafts, key=event_sort_key), start=1)
    ]
    system_records = evidence.get(EvidenceSource.SYSTEM, {}).get("records", [])
    return NormalizationResult(
        case_id=ctx.case_id,
        device=ctx.device,
        events=events,
        host=copy.deepcopy(system_records[0]) if system_records else {},
        users=users,
        source_counts=source_counts,
        warnings=sorted(ctx.warnings, key=_warning_key),
        validation=validation,
    )
