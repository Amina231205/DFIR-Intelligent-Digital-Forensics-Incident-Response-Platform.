"""Synthetic events for the Phase 5 detection tests (no real data).

``Factory`` builds ``NormalizedEvent`` objects whose ``details`` have the same
keys the Phase 3 normalizer produces, with unique event/evidence ids, so rules
can be tested on small, exact scenarios (threshold edges, wrong PID, ...)
without touching the sample evidence.
"""

from __future__ import annotations

import base64
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Optional, Union

from security.detection import DetectionConfig, run_detection
from security.models.schemas import (
    DetectionResult,
    EventType,
    EvidenceSource,
    NormalizedEvent,
    Timeline,
)
from security.timeline import build_timeline
from security.utils.helpers import format_timestamp

BASE = datetime(2026, 10, 8, 7, 0, 0, tzinfo=timezone.utc)
NOW = datetime(2026, 10, 9, 12, 0, 0, tzinfo=timezone.utc)
Moment = Union[int, float, datetime]


def at(seconds: Moment) -> datetime:
    """``BASE`` plus a number of seconds (or the datetime itself)."""
    if isinstance(seconds, datetime):
        return seconds
    return BASE + timedelta(seconds=seconds)


def encode_command(text: str) -> str:
    """Base64 of UTF-16LE: the format of powershell -EncodedCommand."""
    return base64.b64encode(text.encode("utf-16-le")).decode("ascii")


def user_context(username: str, admin: bool, created_at: str,
                 evidence_id: str = "USR-0001", enabled: bool = True) -> dict[str, Any]:
    """Shape of ``details['user_context']`` produced by enrichment."""
    return {"evidence_id": evidence_id, "username": username, "account_type": "local",
            "enabled": enabled, "is_admin": admin,
            "groups": ["Administrators"] if admin else ["Users"], "created_at": created_at}


class Factory:
    """Collects synthetic events; ``timeline()`` builds a Phase 4 timeline."""

    def __init__(self, device: str = "PC-1", case_id: str = "C-1") -> None:
        self.device = device
        self.case_id = case_id
        self.events: list[NormalizedEvent] = []
        self._counters: dict[str, int] = defaultdict(int)

    def _add(self, when: Moment, source: EvidenceSource, prefix: str,
             event_type: EventType, user: Optional[str], details: dict[str, Any],
             device: Optional[str]) -> NormalizedEvent:
        self._counters["event"] += 1
        self._counters[prefix] += 1
        event = NormalizedEvent(
            event_id=f"E-{self._counters['event']:05d}", case_id=self.case_id,
            timestamp=at(when), event_type=event_type, source=source,
            device=device or self.device, user=user,
            evidence_id=f"{prefix}-{self._counters[prefix]:04d}", details=details)
        self.events.append(event)
        return event

    # ----------------------------------------------------------- logons
    def failed_logon(self, when: Moment, user: Optional[str] = "ahmed",
                     ip: Optional[str] = "198.51.100.23", device: Optional[str] = None,
                     reason: Optional[str] = "wrong password") -> NormalizedEvent:
        details = {"windows_event_id": 4625, "logon_type": 10,
                   "logon_type_name": "RemoteInteractive", "source_ip": ip,
                   "failure_reason": reason, "user_context": None}
        return self._add(when, EvidenceSource.EVENTS, "EVL", EventType.LOGON_FAILED,
                         user, details, device)

    def logon(self, when: Moment, user: Optional[str] = "ahmed",
              ip: Optional[str] = "198.51.100.23",
              device: Optional[str] = None) -> NormalizedEvent:
        details = {"windows_event_id": 4624, "logon_type": 10,
                   "logon_type_name": "RemoteInteractive", "source_ip": ip,
                   "user_context": None}
        return self._add(when, EvidenceSource.EVENTS, "EVL", EventType.LOGON_SUCCESS,
                         user, details, device)

    def burst(self, start: Moment, count: int, spacing: float = 10, **kwargs: Any
              ) -> list[NormalizedEvent]:
        """``count`` failed logons, ``spacing`` seconds apart."""
        first = at(start)
        return [self.failed_logon(first + timedelta(seconds=i * spacing), **kwargs)
                for i in range(count)]

    # -------------------------------------------------------- processes
    def process(self, when: Moment, pid: int, name: str = "powershell.exe",
                command_line: Optional[str] = "powershell.exe -NoProfile",
                user: str = "ahmed", parent: Optional[str] = "explorer.exe",
                ppid: int = 100, device: Optional[str] = None,
                context: Optional[dict[str, Any]] = None,
                executable_path: Optional[str] = None,
                sha256: Optional[str] = None) -> NormalizedEvent:
        details = {"pid": pid, "ppid": ppid, "name": name, "parent_name": parent,
                   "command_line": command_line, "executable_path": executable_path,
                   "sha256": sha256, "origin": "event_log", "user_context": context}
        return self._add(when, EvidenceSource.PROCESSES, "PROC",
                         EventType.PROCESS_CREATED, user, details, device)

    def script(self, when: Moment, pid: Optional[int], command: str = "Get-Date",
               user: str = "ahmed", script_path: Optional[str] = None,
               host_application: Optional[str] = None, device: Optional[str] = None,
               context: Optional[dict[str, Any]] = None) -> NormalizedEvent:
        details = {"pid": pid, "command": command, "script_path": script_path,
                   "host_application": host_application, "windows_event_id": 4104,
                   "log": None, "origin": "script_block_log", "user_context": context}
        return self._add(when, EvidenceSource.POWERSHELL, "PS",
                         EventType.POWERSHELL_EXECUTED, user, details, device)

    def connection(self, when: Moment, pid: Optional[int],
                   process_name: str = "powershell.exe",
                   remote: Optional[str] = "8.8.8.8", port: int = 443,
                   direction: str = "outbound", user: Optional[str] = None,
                   device: Optional[str] = None,
                   hostname: Optional[str] = None) -> NormalizedEvent:
        details = {"protocol": "TCP", "direction": direction,
                   "local_address": "10.20.0.15", "local_port": 49000,
                   "remote_address": remote, "remote_port": port, "state": None,
                   "pid": pid, "process_name": process_name, "remote_hostname": hostname,
                   "origin": "event_log", "user_context": None}
        return self._add(when, EvidenceSource.NETWORK, "NET",
                         EventType.NETWORK_CONNECTION, user, details, device)

    # ------------------------------------------------------------ files
    def file(self, when: Moment, path: str = "C:\\Users\\Public\\a.ps1",
             sha256: Optional[str] = "a1" * 32, owner: Optional[str] = "ahmed",
             device: Optional[str] = None) -> NormalizedEvent:
        name = path.replace("/", "\\").rsplit("\\", 1)[-1]
        details = {"path": path, "name": name, "size_bytes": 10, "sha256": sha256,
                   "modified_at": None, "owner": owner, "user_context": None}
        return self._add(when, EvidenceSource.FILES, "FILE", EventType.FILE_CREATED,
                         owner, details, device)

    # --------------------------------------------------------- accounts
    def account(self, when: Moment, actor: Optional[str] = "ahmed",
                target: Optional[str] = "svc_new", device: Optional[str] = None,
                target_context: Optional[dict[str, Any]] = None,
                actor_context: Optional[dict[str, Any]] = None) -> NormalizedEvent:
        details = {"windows_event_id": 4720, "target_user": target,
                   "target_domain": device or self.device, "target_sid": "S-1-5-21-1-2-3-1004",
                   "sam_account_name": target, "subject_domain": device or self.device,
                   "user_context": actor_context, "target_user_context": target_context}
        return self._add(when, EvidenceSource.EVENTS, "EVL", EventType.ACCOUNT_CREATED,
                         actor, details, device)

    def group_add(self, when: Moment, member: Optional[str] = "svc_new",
                  group: Optional[str] = "Administrators", actor: Optional[str] = "ahmed",
                  device: Optional[str] = None) -> NormalizedEvent:
        details = {"windows_event_id": 4732, "group": group, "group_domain": "Builtin",
                   "member": f"{device or self.device}\\{member}" if member else None,
                   "member_name": member, "member_sid": None, "subject_domain": None,
                   "user_context": None, "target_user_context": None}
        return self._add(when, EvidenceSource.EVENTS, "EVL", EventType.GROUP_MEMBER_ADDED,
                         actor, details, device)

    # ---------------------------------------------------------- outputs
    def timeline(self) -> Timeline:
        return build_timeline(self.events, case_id=self.case_id)

    def run(self, config: Optional[DetectionConfig] = None, **kwargs: Any
            ) -> DetectionResult:
        kwargs.setdefault("now", NOW)
        return run_detection(self.timeline(), config=config, **kwargs)


def findings_of(result: DetectionResult, rule_id: str) -> list:
    return [f for f in result.findings if f.rule_id == rule_id]


def summary_of(result: DetectionResult, rule_id: str):
    return next(r for r in result.rules if r.rule_id == rule_id)


def iso(seconds: Moment) -> str:
    return format_timestamp(at(seconds))
