"""Filter a timeline by time range, event type, source, user and device.

    from security.timeline import filter_timeline
    view = filter_timeline(timeline, event_types=["logon_failed"], users="ahmed",
                           start="2026-10-08T07:31:00Z", end="2026-10-08T07:33:00Z")

Semantics:

* Criteria combine with AND; the values inside one criterion combine with OR.
* ``None`` (the default) means "do not filter on this". An EMPTY collection
  is an error, because it would silently match nothing.
* ``start`` and ``end`` are both INCLUSIVE and must be timezone-aware
  (a ``datetime`` or an ISO 8601 string; offsets are converted to UTC).
* ``users`` and ``devices`` match case-insensitively (Windows names are
  case-insensitive). ``users`` matches the entry's ``user`` field only; on
  account_created / group_member_added that is the ACTOR. Entries with no user
  never match a user filter.
* The result is a NEW timeline: the input is untouched, order is preserved,
  ``event_id`` / ``evidence_id`` are unchanged, and ``sequence``, gaps,
  offsets and statistics are recomputed for the selected entries.
"""

from __future__ import annotations

import copy
import dataclasses
from datetime import datetime
from typing import Iterable, Optional, Union

from security.models.schemas import EventType, EvidenceSource, Timeline
from security.timeline.timeline import _assemble
from security.utils.helpers import parse_timestamp

Moment = Union[datetime, str]
Many = Union[str, Iterable[str]]


def _to_utc(value: Optional[Moment], name: str) -> Optional[datetime]:
    if value is None:
        return None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            raise ValueError(
                f"{name} must be timezone-aware (e.g. '2026-10-08T07:31:00Z')")
        return value
    return parse_timestamp(value)  # raises ValueError for naive/invalid text


def _values(value: Optional[Many], name: str) -> Optional[list]:
    """Normalize a single value or an iterable into a list; None stays None."""
    if value is None:
        return None
    items = [value] if isinstance(value, (str, EventType, EvidenceSource)) else list(value)
    if not items:
        raise ValueError(
            f"{name} is empty; pass None to leave this criterion unfiltered")
    return items


def _enum_set(enum_cls, values: Optional[list], name: str):
    """Convert strings/enums to a set of enum members with a helpful error."""
    if values is None:
        return None
    result = set()
    for value in values:
        try:
            result.add(enum_cls(value))
        except ValueError:
            valid = ", ".join(member.value for member in enum_cls)
            raise ValueError(
                f"unknown {name} {value!r}; valid values: {valid}") from None
    return result


def filter_timeline(
    timeline: Timeline,
    *,
    start: Optional[Moment] = None,
    end: Optional[Moment] = None,
    event_types: Optional[Union[EventType, Many]] = None,
    sources: Optional[Union[EvidenceSource, Many]] = None,
    users: Optional[Many] = None,
    devices: Optional[Many] = None,
) -> Timeline:
    """Return a new timeline containing only the matching entries.

    Raises:
        ValueError: naive/invalid ``start``/``end``, ``start`` after ``end``,
            an unknown event type or source, or an empty criterion.
    """
    start_utc = _to_utc(start, "start")
    end_utc = _to_utc(end, "end")
    if start_utc and end_utc and start_utc > end_utc:
        raise ValueError("start is after end")

    type_list = _values(event_types, "event_types")
    source_list = _values(sources, "sources")
    user_list = _values(users, "users")
    device_list = _values(devices, "devices")
    wanted_types = _enum_set(EventType, type_list, "event type")
    wanted_sources = _enum_set(EvidenceSource, source_list, "source")
    wanted_users = {u.casefold() for u in user_list} if user_list else None
    wanted_devices = {d.casefold() for d in device_list} if device_list else None

    selected = [
        dataclasses.replace(entry, details=copy.deepcopy(entry.details))
        for entry in timeline.entries
        if (start_utc is None or entry.timestamp >= start_utc)
        and (end_utc is None or entry.timestamp <= end_utc)
        and (wanted_types is None or entry.event_type in wanted_types)
        and (wanted_sources is None or entry.source in wanted_sources)
        and (wanted_users is None
             or (entry.user is not None and entry.user.casefold() in wanted_users))
        and (wanted_devices is None or entry.device.casefold() in wanted_devices)
    ]
    return _assemble(timeline.case_id, selected)
