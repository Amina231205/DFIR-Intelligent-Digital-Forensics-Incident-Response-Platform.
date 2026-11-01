"""User enrichment: attach account context from users.json to events.

users.json is a SNAPSHOT of accounts, not a log, so it never creates timeline
events. It only answers "what kind of account was this?" (admin? enabled?
local?) for events that mention a user. The context carries the users.json
``evidence_id`` so the lookup itself stays traceable.

Matching is case-insensitive because Windows account names are.
"""

from __future__ import annotations

import copy
from typing import Any, Optional

from security.models.schemas import EventType, EvidenceSource, NormalizedEvent
from security.normalization.mappers import MappingContext

UserContext = dict[str, Any]


def build_user_index(users: list[dict[str, Any]], ctx: MappingContext) -> dict[str, UserContext]:
    """Index users.json records by lowercase username."""
    index: dict[str, UserContext] = {}
    for record in users:
        key = record["username"].casefold()
        if key in index:
            ctx.warn(
                "USERS_DUPLICATE_USERNAME",
                f"{record['record_id']}: username {record['username']!r} "
                f"already appears as {index[key]['evidence_id']}; the first "
                "record is used for enrichment.",
                EvidenceSource.USERS, record["record_id"])
            continue
        index[key] = {
            "evidence_id": record["record_id"],
            "username": record["username"],
            "account_type": record["account_type"],
            "enabled": record["enabled"],
            "is_admin": record["is_admin"],
            "groups": list(record.get("groups") or []),
            "created_at": record["created_at"],
        }
    return index


def _lookup(index: dict[str, UserContext], name: Optional[str]) -> Optional[UserContext]:
    if not name:
        return None
    found = index.get(name.casefold())
    return copy.deepcopy(found) if found else None


def enrich_events(events: list[NormalizedEvent], index: dict[str, UserContext]) -> None:
    """Add ``user_context`` (and ``target_user_context``) to each event's details.

    * every event gets ``user_context``: the acting/involved ``user``'s
      account, or None when the user is unknown or absent;
    * account_created and group_member_added also get
      ``target_user_context`` for the account that was created / added.

    The events are the normalizer's own fresh objects, so editing their
    ``details`` in place never touches the input evidence.
    """
    for event in events:
        event.details["user_context"] = _lookup(index, event.user)
        if event.event_type is EventType.ACCOUNT_CREATED:
            target = event.details.get("target_user")
        elif event.event_type is EventType.GROUP_MEMBER_ADDED:
            target = event.details.get("member_name")
        else:
            continue
        event.details["target_user_context"] = _lookup(index, target)
