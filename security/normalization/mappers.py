"""Map ONE raw evidence record to ONE ``NormalizedEvent``.

Rules shared by every mapper:

* One record in, one event out. Nothing is dropped; unknown Windows event IDs
  become ``other`` events that keep the raw ``data``.
* ``evidence_id`` is the record's ``record_id`` (traceability).
* ``details`` has a FIXED set of keys per event type; a missing value is
  ``None``, so the backend and frontend never face a changing shape.
* Mappers never modify their input and never raise because of a missing
  Windows ``EventData`` field: they set ``None`` and add a warning.

The events returned here are DRAFTS: ``event_id`` is empty and users are not
enriched yet. The normalizer orders the drafts and assigns the final IDs.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from security.models.schemas import (
    EventType,
    EvidenceSource,
    NormalizationWarning,
    NormalizedEvent,
)
from security.utils.helpers import parse_timestamp

# Windows Security-log events the MVP understands (contract section 4).
SECURITY_EVENT_TYPES: dict[int, EventType] = {
    4624: EventType.LOGON_SUCCESS,
    4625: EventType.LOGON_FAILED,
    4720: EventType.ACCOUNT_CREATED,
    4732: EventType.GROUP_MEMBER_ADDED,
}
# EventData fields we expect per event ID; absence produces a warning.
EXPECTED_DATA_FIELDS: dict[int, tuple[str, ...]] = {
    4624: ("TargetUserName",),
    4625: ("TargetUserName",),
    4720: ("TargetUserName", "SubjectUserName"),
    4732: ("MemberName", "TargetUserName", "SubjectUserName"),
}
LOGON_TYPE_NAMES: dict[int, str] = {
    2: "Interactive", 3: "Network", 4: "Batch", 5: "Service", 7: "Unlock",
    8: "NetworkCleartext", 9: "NewCredentials", 10: "RemoteInteractive",
    11: "CachedInteractive",
}
# Keys are lowercase hex of the Status / SubStatus codes of event 4625.
FAILURE_REASONS: dict[str, str] = {
    "0xc0000064": "user name does not exist",
    "0xc000006a": "wrong password",
    "0xc000006d": "bad user name or authentication information",
    "0xc000006e": "account restriction",
    "0xc000006f": "outside permitted logon hours",
    "0xc0000070": "workstation restriction",
    "0xc0000071": "password expired",
    "0xc0000072": "account disabled",
    "0xc0000234": "account locked out",
}


@dataclass
class MappingContext:
    """Case identity plus the list that collects warnings."""

    case_id: str
    device: str
    warnings: list[NormalizationWarning] = field(default_factory=list)

    def warn(self, code: str, message: str, source: EvidenceSource,
             evidence_id: str) -> None:
        self.warnings.append(
            NormalizationWarning(code, message, source, evidence_id))


# ------------------------------------------------------------------ helpers
def clean(value: Any) -> Optional[str]:
    """Windows EventData uses '-' or '' for "not applicable": return None."""
    if value is None:
        return None
    text = str(value).strip()
    return None if text in ("", "-") else text


def _opt(value: Any) -> Any:
    """Optional contract field: null and blank strings both become None."""
    if value is None or (isinstance(value, str) and not value.strip()):
        return None
    return value


def _draft(record: dict[str, Any], ctx: MappingContext, source: EvidenceSource,
           event_type: EventType, user: Optional[str],
           details: dict[str, Any]) -> NormalizedEvent:
    return NormalizedEvent(
        event_id="",  # assigned by the normalizer after ordering
        case_id=ctx.case_id,
        timestamp=parse_timestamp(record["timestamp"]),
        event_type=event_type,
        source=source,
        device=ctx.device,
        user=user,
        evidence_id=record["record_id"],
        details=details,
    )


# --------------------------------------------------------- events.json (EVL)
def map_event_record(record: dict[str, Any], ctx: MappingContext) -> NormalizedEvent:
    """Windows Event Log record -> logon / account / other event."""
    source = EvidenceSource.EVENTS
    data: dict[str, Any] = record["data"]
    windows_id: int = record["event_id"]
    channel: str = record["channel"]
    base = {
        "windows_event_id": windows_id,
        "channel": channel,
        "provider": record["provider"],
        "record_number": record.get("record_number"),
    }

    # A given ID only means "logon" etc. in the Security log.
    event_type = (SECURITY_EVENT_TYPES.get(windows_id)
                  if channel.casefold() == "security" else None)
    if event_type is None:
        details = {**base, "data": copy.deepcopy(data)}
        return _draft(record, ctx, source, EventType.OTHER, None, details)

    for name in EXPECTED_DATA_FIELDS[windows_id]:
        if clean(data.get(name)) is None:
            ctx.warn(
                "EVENT_DATA_MISSING_FIELD",
                f"{record['record_id']}: Windows event {windows_id} has no "
                f"usable '{name}' in its data; the related value is null.",
                source, record["record_id"])

    if event_type in (EventType.LOGON_SUCCESS, EventType.LOGON_FAILED):
        return _map_logon(record, ctx, data, base, event_type)
    if event_type is EventType.ACCOUNT_CREATED:
        details = {
            **base,
            "target_user": clean(data.get("TargetUserName")),
            "target_domain": clean(data.get("TargetDomainName")),
            "target_sid": clean(data.get("TargetSid")),
            "sam_account_name": clean(data.get("SamAccountName")),
            "subject_domain": clean(data.get("SubjectDomainName")),
        }
        # user = the ACTOR who created the account; the new account is in details
        return _draft(record, ctx, source, event_type,
                      clean(data.get("SubjectUserName")), details)

    member = clean(data.get("MemberName"))
    details = {
        **base,
        "group": clean(data.get("TargetUserName")),
        "group_domain": clean(data.get("TargetDomainName")),
        "member": member,
        "member_name": member.rsplit("\\", 1)[-1] if member else None,
        "member_sid": clean(data.get("MemberSid")),
        "subject_domain": clean(data.get("SubjectDomainName")),
    }
    return _draft(record, ctx, source, event_type,
                  clean(data.get("SubjectUserName")), details)


def _map_logon(record: dict[str, Any], ctx: MappingContext,
               data: dict[str, Any], base: dict[str, Any],
               event_type: EventType) -> NormalizedEvent:
    raw_type = clean(data.get("LogonType"))
    logon_type: Optional[int] = None
    if raw_type is not None:
        try:
            logon_type = int(raw_type)
        except ValueError:
            ctx.warn(
                "EVENT_DATA_INVALID",
                f"{record['record_id']}: LogonType {raw_type!r} is not an "
                "integer; logon_type is null.",
                EvidenceSource.EVENTS, record["record_id"])
    details: dict[str, Any] = {
        **base,
        "logon_type": logon_type,
        "logon_type_name": LOGON_TYPE_NAMES.get(logon_type),
        "source_ip": clean(data.get("IpAddress")),
        "workstation": clean(data.get("WorkstationName")),
        "target_domain": clean(data.get("TargetDomainName")),
        "logon_process": clean(data.get("LogonProcessName")),
        "authentication_package": clean(data.get("AuthenticationPackageName")),
    }
    if event_type is EventType.LOGON_FAILED:
        status = clean(data.get("Status"))
        sub_status = clean(data.get("SubStatus"))
        reason = None
        for code in (sub_status, status):
            if code and code.lower() in FAILURE_REASONS:
                reason = FAILURE_REASONS[code.lower()]
                break
        details.update(status=status, sub_status=sub_status,
                       failure_reason=reason)
    return _draft(record, ctx, EvidenceSource.EVENTS, event_type,
                  clean(data.get("TargetUserName")), details)


# ------------------------------------------------------ processes.json (PROC)
def map_process_record(record: dict[str, Any], ctx: MappingContext) -> NormalizedEvent:
    details = {
        "pid": record["pid"],
        "ppid": record["ppid"],
        "name": record["name"],
        "parent_name": _opt(record.get("parent_name")),
        "command_line": record.get("command_line"),  # may be null by contract
        "executable_path": _opt(record.get("executable_path")),
        "sha256": _opt(record.get("sha256")),
        "origin": _opt(record.get("origin")),
    }
    return _draft(record, ctx, EvidenceSource.PROCESSES,
                  EventType.PROCESS_CREATED, record["user"], details)


# --------------------------------------------------------- network.json (NET)
def map_network_record(record: dict[str, Any], ctx: MappingContext) -> NormalizedEvent:
    """Connection -> network_connection.

    NOTE: no "is external" flag is derived here. What counts as internal is a
    detection-policy decision (Python's ``ipaddress`` even treats the
    documentation ranges used in our samples as private), so Phase 5 owns it.
    """
    details = {
        "protocol": record["protocol"],
        "direction": record["direction"],
        "local_address": record["local_address"],
        "local_port": record["local_port"],
        "remote_address": record["remote_address"],
        "remote_port": record["remote_port"],
        "state": _opt(record.get("state")),
        "pid": record["pid"],
        "process_name": record["process_name"],
        "remote_hostname": _opt(record.get("remote_hostname")),
        "origin": _opt(record.get("origin")),
    }
    return _draft(record, ctx, EvidenceSource.NETWORK,
                  EventType.NETWORK_CONNECTION, _opt(record.get("user")), details)


# ---------------------------------------------------- powershell.json (PS)
def map_powershell_record(record: dict[str, Any], ctx: MappingContext) -> NormalizedEvent:
    details = {
        "pid": record["pid"],
        "command": record["command"],
        "script_path": _opt(record.get("script_path")),
        "host_application": _opt(record.get("host_application")),
        "windows_event_id": record.get("event_id"),
        "log": _opt(record.get("log")),
        "origin": _opt(record.get("origin")),
    }
    return _draft(record, ctx, EvidenceSource.POWERSHELL,
                  EventType.POWERSHELL_EXECUTED, record["user"], details)


# ------------------------------------------------------------ files.json (FILE)
def map_file_record(record: dict[str, Any], ctx: MappingContext) -> NormalizedEvent:
    """File record -> file_created (``timestamp`` is the creation time)."""
    owner = _opt(record.get("owner"))
    details = {
        "path": record["path"],
        "name": record["name"],
        "size_bytes": record["size_bytes"],
        "sha256": record["sha256"],
        "modified_at": _opt(record.get("modified_at")),
        "owner": owner,
    }
    return _draft(record, ctx, EvidenceSource.FILES,
                  EventType.FILE_CREATED, owner, details)


Mapper = Callable[[dict[str, Any], MappingContext], NormalizedEvent]

# Sources that produce timeline events, in tie-break order (see normalizer).
# users.json and system.json are deliberately NOT here.
MAPPERS: dict[EvidenceSource, Mapper] = {
    EvidenceSource.EVENTS: map_event_record,
    EvidenceSource.PROCESSES: map_process_record,
    EvidenceSource.NETWORK: map_network_record,
    EvidenceSource.POWERSHELL: map_powershell_record,
    EvidenceSource.FILES: map_file_record,
}
