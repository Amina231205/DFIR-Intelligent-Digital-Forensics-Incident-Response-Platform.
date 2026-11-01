"""Timeline reconstruction (Module 3) - build the incident timeline.

    from security.timeline import build_case_timeline
    timeline = build_case_timeline("security/sample_evidence/INC-001")
    for entry in timeline.entries:
        print(entry.sequence, entry.timestamp, entry.summary)

The timeline answers: what happened -> when -> on which device -> under which
user -> what happened next (``gap_from_previous_seconds``).

Guarantees:

* **Read-only.** Input events are never modified or re-ordered in place;
  entries hold copies of ``details``.
* **Deterministic.** Order is ``event_sort_key`` from normalization (time,
  then source, then record number, then record id), so identical timestamps
  always resolve the same way and the result does not depend on input order.
* **Lossless.** Every ``NormalizedEvent`` field survives on its entry
  (``entry.to_event()`` rebuilds the original event).
"""

from __future__ import annotations

import copy
import dataclasses
from collections import Counter
from pathlib import Path
from typing import Iterable, Optional, Union

from security.models.schemas import (
    NormalizationResult,
    NormalizedEvent,
    Timeline,
    TimelineEntry,
)
from security.normalization import event_sort_key, normalize_case
from security.timeline.summaries import describe_event


def build_timeline(
    events: Iterable[NormalizedEvent],
    case_id: Optional[str] = None,
) -> Timeline:
    """Build a timeline from normalized events.

    Args:
        events: normalized events in any order (they are copied, not changed).
        case_id: required only to label an EMPTY timeline; otherwise taken
            from the events and checked against them.

    Raises:
        ValueError: an event has no ``event_id`` (not normalized yet), two
            events share an ``event_id``, or the events/``case_id`` disagree
            about the case.
    """
    ordered = sorted(events, key=event_sort_key)

    seen: set[str] = set()
    for event in ordered:
        if not event.event_id:
            raise ValueError(
                f"event from {event.evidence_id} has no event_id; run "
                "normalization before building a timeline")
        if event.event_id in seen:
            raise ValueError(f"duplicate event_id {event.event_id!r}")
        seen.add(event.event_id)

    case_ids = {event.case_id for event in ordered}
    if case_id is not None:
        case_ids.add(case_id)
    if len(case_ids) > 1:
        raise ValueError(
            f"a timeline covers one case, got case_ids {sorted(case_ids)}")

    entries = [_entry_from_event(event) for event in ordered]
    return _assemble(next(iter(case_ids), None), entries)


def build_timeline_from_result(result: NormalizationResult) -> Timeline:
    """Build the timeline of a normalization result (labels it when empty)."""
    return build_timeline(result.events, case_id=result.case_id)


def build_case_timeline(folder: Union[str, Path]) -> Timeline:
    """Validate, normalize and build the timeline of an evidence folder.

    Raises:
        EvidenceNotValidError: the evidence failed validation.
    """
    return build_timeline_from_result(normalize_case(folder))


# ------------------------------------------------------------------ internals
def _entry_from_event(event: NormalizedEvent) -> TimelineEntry:
    """Entry with placeholder numbering; ``_assemble`` fills it in."""
    return TimelineEntry(
        sequence=0,
        event_id=event.event_id,
        case_id=event.case_id,
        timestamp=event.timestamp,
        event_type=event.event_type,
        source=event.source,
        device=event.device,
        user=event.user,
        evidence_id=event.evidence_id,
        evidence_file=event.evidence_file,
        summary=describe_event(event),
        gap_from_previous_seconds=None,
        offset_from_start_seconds=0.0,
        details=copy.deepcopy(event.details),
    )


def _assemble(case_id: Optional[str], entries: list[TimelineEntry]) -> Timeline:
    """Number ordered entries and compute the timeline-level statistics.

    Used for new timelines AND for filtered ones, which is why a filtered
    timeline is as self-consistent as a full one.
    """
    numbered: list[TimelineEntry] = []
    for index, entry in enumerate(entries):
        if index == 0:
            gap, offset = None, 0.0
        else:
            gap = round((entry.timestamp - entries[index - 1].timestamp)
                        .total_seconds(), 6)
            offset = round((entry.timestamp - entries[0].timestamp)
                           .total_seconds(), 6)
        numbered.append(dataclasses.replace(
            entry, sequence=index + 1, gap_from_previous_seconds=gap,
            offset_from_start_seconds=offset))

    start = numbered[0].timestamp if numbered else None
    end = numbered[-1].timestamp if numbered else None
    return Timeline(
        case_id=case_id,
        devices=sorted({e.device for e in numbered}, key=lambda d: (d.casefold(), d)),
        start=start,
        end=end,
        duration_seconds=(round((end - start).total_seconds(), 6)
                          if start and end else 0.0),
        event_count=len(numbered),
        counts_by_type=dict(sorted(Counter(e.event_type.value for e in numbered).items())),
        counts_by_source=dict(sorted(Counter(e.source.value for e in numbered).items())),
        users=sorted({e.user for e in numbered if e.user},
                     key=lambda u: (u.casefold(), u)),
        entries=numbered,
    )
