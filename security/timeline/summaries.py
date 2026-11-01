"""Neutral one-line descriptions of normalized events.

A summary only restates facts already present in the event ("Failed logon
(RemoteInteractive) for ahmed from 198.51.100.23"). It never interprets them:
words such as "suspicious" or "attack" belong to detection (Phase 5), not here.

Output is plain ASCII punctuation (``->``, not an arrow glyph) so it prints
safely on any console, including legacy Windows code pages. Missing values
read as "unknown ..." instead of raising.
"""

from __future__ import annotations

from typing import Any, Optional

from security.models.schemas import EventType, NormalizedEvent


def _quote(value: Optional[str], fallback: str) -> str:
    return f"'{value}'" if value else fallback


def _logon(event: NormalizedEvent) -> str:
    d = event.details
    failed = event.event_type is EventType.LOGON_FAILED
    if d.get("logon_type_name"):
        kind = f" ({d['logon_type_name']})"
    elif d.get("logon_type") is not None:
        kind = f" (type {d['logon_type']})"
    else:
        kind = ""
    origin = f" from {d['source_ip']}" if d.get("source_ip") else ""
    reason = f": {d['failure_reason']}" if failed and d.get("failure_reason") else ""
    return (f"{'Failed' if failed else 'Successful'} logon{kind} for "
            f"{event.user or 'unknown user'}{origin}{reason}")


def _process(event: NormalizedEvent) -> str:
    d = event.details
    text = f"Process created: {d.get('name') or 'unknown'} (PID {d.get('pid')})"
    if event.user:
        text += f" by {event.user}"
    if d.get("parent_name"):
        text += f", parent {d['parent_name']}"
    return text


def _network(event: NormalizedEvent) -> str:
    d = event.details
    local = f"{d.get('local_address')}:{d.get('local_port')}"
    remote = f"{d.get('remote_address')}:{d.get('remote_port')}"
    protocol = d.get("protocol") or "?"
    if d.get("direction") == "inbound":
        text = f"Inbound {protocol} {remote} -> {local}"
    else:
        text = f"Outbound {protocol} {local} -> {remote}"
    extras = [d[k] for k in ("process_name", "remote_hostname") if d.get(k)]
    return f"{text} ({', '.join(extras)})" if extras else text


def _powershell(event: NormalizedEvent) -> str:
    d = event.details
    label = ("PowerShell command history entry"
             if d.get("origin") == "psreadline_history"
             else "PowerShell script block")
    text = f"{label} by {event.user or 'unknown user'} (PID {d.get('pid')})"
    if d.get("script_path"):
        text += f", script {d['script_path']}"
    return text


def _file(event: NormalizedEvent) -> str:
    d = event.details
    text = f"File created: {d.get('path') or d.get('name') or 'unknown'}"
    if d.get("size_bytes") is not None:
        text += f" ({d['size_bytes']} bytes)"
    if d.get("owner"):
        text += f", owner {d['owner']}"
    return text


def _account_created(event: NormalizedEvent) -> str:
    target = _quote(event.details.get("target_user"), "unknown account")
    return f"Account {target} created by {event.user or 'unknown user'}"


def _group_member_added(event: NormalizedEvent) -> str:
    d = event.details
    member = _quote(d.get("member_name") or d.get("member"), "unknown account")
    group = _quote(d.get("group"), "unknown group")
    return f"{member} added to group {group} by {event.user or 'unknown user'}"


def _other(event: NormalizedEvent) -> str:
    d: dict[str, Any] = event.details
    return (f"Windows event {d.get('windows_event_id', 'unknown')} "
            f"in {d.get('channel') or 'unknown'} log")


_DESCRIBERS = {
    EventType.LOGON_SUCCESS: _logon,
    EventType.LOGON_FAILED: _logon,
    EventType.PROCESS_CREATED: _process,
    EventType.NETWORK_CONNECTION: _network,
    EventType.POWERSHELL_EXECUTED: _powershell,
    EventType.FILE_CREATED: _file,
    EventType.ACCOUNT_CREATED: _account_created,
    EventType.GROUP_MEMBER_ADDED: _group_member_added,
    EventType.OTHER: _other,
}


def describe_event(event: NormalizedEvent) -> str:
    """Return the neutral one-line summary for ``event``."""
    return _DESCRIBERS[event.event_type](event)
