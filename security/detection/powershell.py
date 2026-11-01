"""DET-002: suspicious PowerShell activity.

PowerShell is a normal administration tool, so running it is never a finding.
A finding needs ``min_indicators`` (default 2) DISTINCT, explicitly defined
indicators attached to ONE PowerShell execution context.

EXECUTION CONTEXT
-----------------
A context is one PowerShell process, identified by (device, PID):

* anchor: a ``process_created`` event whose name is in
  ``powershell_process_names``; if the same PID is reused later, each start is
  its own context. When no process record exists, the first PowerShell
  script-block record for that PID becomes the anchor (and the finding says
  that the command line and parent were unavailable).
* attached records: ``powershell_executed`` events and OUTBOUND
  ``network_connection`` events, but only when ALL hold: same device, same
  PID, at/after the anchor time and at most ``correlation_window_seconds``
  after it, and the user (when both sides carry one) matches. A connection
  must also be made by a PowerShell-named process. Closeness in time alone
  never attaches anything: events with another PID, device, user or process
  name are never attached, and a connection with no matching PowerShell
  anchor is reported as a data gap instead.

INDICATORS (``POWERSHELL_INDICATORS``; each can be disabled)
------------------------------------------------------------
encoded_command           -EncodedCommand/-e/-enc... followed by a Base64 value
hidden_window             -WindowStyle/-w with a value in hidden_window_values
execution_policy_bypass   -ExecutionPolicy/-ep with a value in execution_policy_values
download_cradle           script text matches a download_patterns regex
invoke_expression         script text matches an invoke_expression_patterns regex
unusual_parent            parent process name is in unusual_parents
user_writable_script_path -File argument or script path under writable_path_fragments
external_connection       attached outbound connection to an address the IP policy
                          calls external (NOT a verdict that the host is malicious)

Texts scanned: the process command line, each attached record's script text
and launching command line, and the decoded form of any Base64 -EncodedCommand
argument (one level). ``-NoProfile`` is deliberately NOT an indicator: it is
common in legitimate scheduled scripts. Only ``-`` parameters are parsed (not
``/`` style). Values are never executed; decoding only reads text.
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Callable, Optional

from security.detection.base import (
    Rule, RuleContext, RuleOutput, build_finding, format_ids, raise_severity,
    snippet, users_compatible)
from security.detection.config import POWERSHELL_INDICATORS, PowerShellConfig
from security.detection.ip_policy import classify_ip
from security.models.schemas import (
    Confidence, EventType, Finding, NormalizedEvent, Severity)
from security.normalization import event_sort_key
from security.utils.helpers import format_timestamp

INDICATOR_DESCRIPTIONS: dict[str, str] = {
    "encoded_command": "command line passes a Base64-encoded command",
    "hidden_window": "PowerShell started with a hidden window",
    "execution_policy_bypass": "execution policy bypassed for this session",
    "download_cradle": "script text uses a download function",
    "invoke_expression": "script text evaluates a string as code",
    "unusual_parent": "PowerShell was started by a process that does not normally start it",
    "user_writable_script_path": "script located in a user-writable folder",
    "external_connection": "same process made an outbound connection to an external address",
}
_TOKEN = re.compile(r'"[^"]*"|\'[^\']*\'|\S+')
_BASE64 = re.compile(r"[A-Za-z0-9+/=]{8,}")
_MAX_ENCODED_CHARS = 200_000


# ------------------------------------------------------------ text analysis
def tokenize(text: str) -> list[str]:
    """Split a command line into tokens, removing surrounding quotes."""
    return [t.strip("\"'") for t in _TOKEN.findall(text)]


def flag_values(tokens: list[str], accepts: Callable[[str], bool]) -> list[tuple[str, str]]:
    """(flag token, value) for every ``-flag`` whose lowercase name is accepted.

    The value is the text after ``-flag:`` or the next token.
    """
    found = []
    for index, token in enumerate(tokens):
        if len(token) < 2 or token[0] != "-":
            continue
        name, separator, inline = token[1:].partition(":")
        if not accepts(name.casefold()):
            continue
        if separator:
            found.append((token, inline))
        elif index + 1 < len(tokens):
            found.append((token, tokens[index + 1]))
    return found


def decode_encoded_command(value: str) -> Optional[str]:
    """Decode a PowerShell -EncodedCommand argument (Base64 of UTF-16LE).

    Returns None when ``value`` is not valid Base64, not valid UTF-16LE or
    not printable text. Reads only; nothing is executed.
    """
    if len(value) > _MAX_ENCODED_CHARS:
        return None
    try:
        raw = base64.b64decode(value, validate=True)
        text = raw.decode("utf-16-le")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None
    if not text or not all(ch.isprintable() or ch in "\r\n\t" for ch in text):
        return None
    return text


@dataclass(frozen=True)
class Match:
    """One indicator hit, with the exact evidence it came from."""

    indicator: str
    event: NormalizedEvent
    field: str
    text: str


class _Scanner:
    """Compiled patterns for one rule configuration."""

    def __init__(self, cfg: PowerShellConfig) -> None:
        self.cfg = cfg
        self.enabled = set(cfg.enabled_indicators)
        self.download = [re.compile(p, re.IGNORECASE) for p in cfg.download_patterns]
        self.iex = [re.compile(p, re.IGNORECASE) for p in cfg.invoke_expression_patterns]

    def is_writable(self, path: str) -> bool:
        normalized = path.replace("/", "\\").casefold()
        return any(fragment in normalized for fragment in self.cfg.writable_path_fragments)

    def scan(self, text: str, field_name: str, event: NormalizedEvent,
             decode: bool = True) -> list[Match]:
        cfg, on = self.cfg, self.enabled
        tokens = tokenize(text)
        hits: list[Match] = []
        if "hidden_window" in on:
            for flag, value in flag_values(
                    tokens, lambda n: bool(n) and "windowstyle".startswith(n)):
                if value.casefold() in cfg.hidden_window_values:
                    hits.append(Match("hidden_window", event, field_name, f"{flag} {value}"))
        if "execution_policy_bypass" in on:
            for flag, value in flag_values(
                    tokens, lambda n: n == "ep"
                    or (len(n) >= 2 and "executionpolicy".startswith(n))):
                if value.casefold() in cfg.execution_policy_values:
                    hits.append(Match("execution_policy_bypass", event, field_name,
                                      f"{flag} {value}"))
        if "user_writable_script_path" in on:
            for flag, value in flag_values(tokens, lambda n: bool(n) and "file".startswith(n)):
                if self.is_writable(value):
                    hits.append(Match("user_writable_script_path", event, field_name,
                                      snippet(f"{flag} {value}")))
        if "download_cradle" in on:
            hits += [Match("download_cradle", event, field_name, m.group(0))
                     for p in self.download for m in [p.search(text)] if m]
        if "invoke_expression" in on:
            hits += [Match("invoke_expression", event, field_name, m.group(0))
                     for p in self.iex for m in [p.search(text)] if m]
        # -EncodedCommand, any unique prefix (-e, -en, -enc ...) and the alias -ec
        for flag, value in flag_values(
                tokens, lambda n: bool(n) and (
                    "encodedcommand".startswith(n) or n == "ec")):
            if not _BASE64.fullmatch(value):
                continue
            if "encoded_command" in on:
                hits.append(Match("encoded_command", event, field_name,
                                  f"{flag} <Base64, {len(value)} characters>"))
            decoded = decode_encoded_command(value) if decode else None
            if decoded:
                hits += self.scan(decoded, f"{field_name} (decoded)", event, decode=False)
        return hits


# ----------------------------------------------------------------- the rule
@dataclass
class _Context:
    device: str
    pid: int
    start: datetime
    process: Optional[NormalizedEvent] = None
    user: Optional[str] = None
    scripts: list[NormalizedEvent] = field(default_factory=list)
    connections: list[NormalizedEvent] = field(default_factory=list)


def _lower(value: Any) -> str:
    return value.casefold() if isinstance(value, str) else ""


class PowerShellRule(Rule):
    rule_id = "DET-002"
    name = "Suspicious PowerShell Activity"

    def __init__(self, config: Optional[PowerShellConfig] = None) -> None:
        self.config = config or PowerShellConfig()
        self._scanner = _Scanner(self.config)

    def evaluate(self, context: RuleContext) -> RuleOutput:
        cfg = self.config
        names = set(cfg.powershell_process_names)
        window = timedelta(seconds=cfg.correlation_window_seconds)
        gaps: set[str] = set()

        processes = [e for e in context.events if e.event_type is EventType.PROCESS_CREATED
                     and _lower(e.details.get("name")) in names]
        scripts = [e for e in context.events if e.event_type is EventType.POWERSHELL_EXECUTED]
        connections = [e for e in context.events
                       if e.event_type is EventType.NETWORK_CONNECTION
                       and e.details.get("direction") == "outbound"
                       and _lower(e.details.get("process_name")) in names]

        anchors: dict[tuple, list[_Context]] = {}
        for event in processes:
            pid = event.details.get("pid")
            if pid is None:
                gaps.add(f"{event.evidence_id}: PowerShell process record has no pid; "
                         "it cannot be correlated")
                continue
            anchors.setdefault((event.device.casefold(), pid), []).append(
                _Context(event.device, pid, event.timestamp, event, event.user))

        def assign(event: NormalizedEvent, key: tuple) -> Optional[_Context]:
            candidates = [c for c in anchors.get(key, [])
                          if c.start <= event.timestamp
                          and users_compatible(c.user, event.user)]
            if candidates and event.timestamp - candidates[-1].start <= window:
                return candidates[-1]
            return None

        for event in scripts:
            pid = event.details.get("pid")
            if pid is None:
                gaps.add(f"{event.evidence_id}: PowerShell record has no pid; it cannot "
                         "be attached to a process")
                continue
            key = (event.device.casefold(), pid)
            owner = assign(event, key)
            if owner is None:   # no process record covers it: anchor on the record itself
                owner = _Context(event.device, pid, event.timestamp, None, event.user)
                anchors.setdefault(key, []).append(owner)
                anchors[key].sort(key=lambda c: c.start)
                gaps.add(f"no process record for PID {pid} on {event.device} near "
                         f"{event.evidence_id}: command line and parent process are "
                         "unavailable (only PowerShell records were evaluated)")
            owner.scripts.append(event)

        unattached: list[str] = []
        for event in connections:
            pid = event.details.get("pid")
            owner = assign(event, (event.device.casefold(), pid)) if pid is not None else None
            if owner is None:
                unattached.append(event.event_id)
            else:
                owner.connections.append(event)
        if unattached:
            gaps.add(f"{len(unattached)} outbound connection(s) by a PowerShell-named "
                     "process have no matching PowerShell process or script record "
                     f"(same device, PID, user and time window) and were not used: "
                     f"{format_ids(unattached)}")

        findings: list[Finding] = []
        for owners in anchors.values():
            for owner in owners:
                finding = self._evaluate_context(context, owner, gaps)
                if finding is not None:
                    findings.append(finding)
        findings.sort(key=lambda f: (f.first_seen, f.supporting_events))
        considered = len(processes) + len(scripts) + len(connections)
        return RuleOutput(findings, considered, sorted(gaps))

    # ------------------------------------------------------------------
    def _evaluate_context(self, rule_context: RuleContext, owner: _Context,
                          gaps: set[str]) -> Optional[Finding]:
        cfg, scanner = self.config, self._scanner
        matches: list[Match] = []
        process = owner.process
        label = f"PID {owner.pid} on {owner.device}"

        if process is not None:
            command_line = process.details.get("command_line")
            if isinstance(command_line, str) and command_line.strip():
                matches += scanner.scan(command_line, "command_line", process)
            else:
                gaps.add(f"{process.evidence_id} ({label}) has no command line: "
                         "command-line indicators were not evaluated for it")
            parent = process.details.get("parent_name")
            if "unusual_parent" in scanner.enabled:
                if not parent:
                    gaps.add(f"{process.evidence_id} ({label}) has no parent_name: "
                             "unusual_parent was not evaluated for it")
                elif parent.casefold() in cfg.unusual_parents:
                    matches.append(Match("unusual_parent", process, "parent_name", parent))

        for script in owner.scripts:
            for field_name in ("command", "host_application"):
                value = script.details.get(field_name)
                if isinstance(value, str) and value.strip():
                    matches += scanner.scan(value, field_name, script)
            path = script.details.get("script_path")
            if ("user_writable_script_path" in scanner.enabled
                    and isinstance(path, str) and scanner.is_writable(path)):
                matches.append(Match("user_writable_script_path", script,
                                     "script_path", snippet(path)))

        linked_connections: list[NormalizedEvent] = []
        if "external_connection" in scanner.enabled:
            for connection in owner.connections:
                remote = connection.details.get("remote_address")
                verdict = cfg.ip_policy.is_external(remote)
                if verdict is None:
                    gaps.add(f"{connection.evidence_id}: remote_address {remote!r} is "
                             f"{classify_ip(remote).value}; it cannot be classified as "
                             "external or internal")
                elif verdict:
                    linked_connections.append(connection)
                    port = connection.details.get("remote_port")
                    matches.append(Match(
                        "external_connection", connection, "remote_address",
                        f"{remote}:{port} ({classify_ip(remote).value})"))

        order = {name: i for i, name in enumerate(POWERSHELL_INDICATORS)}
        distinct = sorted({m.indicator for m in matches}, key=order.get)
        if len(distinct) < cfg.min_indicators:
            return None
        return self._build(rule_context, owner, matches, distinct, linked_connections)

    def _build(self, rule_context: RuleContext, owner: _Context, matches: list[Match],
               distinct: list[str], linked_connections: list[NormalizedEvent]) -> Finding:
        cfg = self.config
        process = owner.process
        order = {name: i for i, name in enumerate(POWERSHELL_INDICATORS)}
        ordered = sorted(
            {(m.indicator, m.event.event_id, m.field, m.text): m for m in matches}.values(),
            key=lambda m: (order[m.indicator], event_sort_key(m.event), m.field))
        indicators = [{
            "indicator": m.indicator,
            "description": INDICATOR_DESCRIPTIONS[m.indicator],
            "matched_text": m.text,
            "field": m.field,
            "event_id": m.event.event_id,
            "evidence_id": m.event.evidence_id,
            "evidence_file": m.event.evidence_file,
        } for m in ordered]

        evidence_files = sorted({m.event.evidence_file for m in matches})
        n, files = len(distinct), len(evidence_files)
        if n >= 3 and files >= 2:
            confidence = Confidence.HIGH
        elif (n >= 2 and files >= 2) or n >= 3:
            confidence = Confidence.MEDIUM
        else:
            confidence = Confidence.LOW
        confidence_factors = [
            f"{n} distinct indicator(s) matched from {files} evidence file(s) "
            f"({', '.join(evidence_files)}): {confidence.value}"]

        involved = ([process] if process else []) + owner.scripts + linked_connections
        admin_records = sorted({
            (e.details["user_context"]["evidence_id"], "users.json") for e in involved
            if (e.details.get("user_context") or {}).get("is_admin") is True})
        is_admin = bool(admin_records)
        severity = Severity.MEDIUM if n >= 2 else Severity.LOW
        severity_factors = [f"base level for {n} matched indicator(s): {severity.value}"]
        steps = 0
        if "external_connection" in distinct:
            steps += 1
            severity_factors.append(
                "+1: the same process made an outbound connection to an external address")
        if is_admin:
            steps += 1
            severity_factors.append(
                "+1: the acting account is a member of Administrators (users.json)")
        severity = raise_severity(severity, steps)

        user = owner.user or next((e.user for e in involved if e.user), None)
        supporting = [m.event for m in matches] + ([process] if process else [])
        correlated = self._correlation_notes(owner)
        ctx: dict[str, Any] = {
            "process": {
                "device": owner.device,
                "pid": owner.pid,
                "start": format_timestamp(owner.start),
                "process_event_id": process.event_id if process else None,
                "process_evidence_id": process.evidence_id if process else None,
                "parent_name": process.details.get("parent_name") if process else None,
                "command_line_available": bool(
                    process and isinstance(process.details.get("command_line"), str)
                    and process.details["command_line"].strip()),
            },
            "distinct_indicators": n,
            "min_indicators": cfg.min_indicators,
            "evidence_files_with_indicators": evidence_files,
            "correlation_window_seconds": cfg.correlation_window_seconds,
            "correlated_records": correlated,
            "powershell_records_in_context": len(owner.scripts),
            "external_classes": sorted(c.value for c in cfg.ip_policy.external_classes),
        }
        description = (
            f"PowerShell process PID {owner.pid} on {owner.device}"
            f"{f' (user {user})' if user else ''} matched {n} configured indicators: "
            f"{', '.join(distinct)}. Indicators are heuristics, not proof of malicious "
            "intent.")
        reason = (f"{n} distinct indicators matched (minimum {cfg.min_indicators}) for "
                  f"one PowerShell execution context: {', '.join(distinct)}.")
        return build_finding(
            self, rule_context, severity=severity, confidence=confidence,
            device=owner.device, user=user, description=description, reason=reason,
            supporting=supporting, matched_indicators=indicators, finding_context=ctx,
            severity_factors=severity_factors, confidence_factors=confidence_factors,
            extra_evidence=admin_records if is_admin else ())

    def _correlation_notes(self, owner: _Context) -> list[dict[str, Any]]:
        """Why each attached record was linked to this process (auditable)."""
        window = self.config.correlation_window_seconds
        notes = []
        for kind, events in (("powershell_record", owner.scripts),
                             ("network_connection", owner.connections)):
            for event in events:
                if event.user and owner.user:
                    user_basis = f"same user '{event.user}'"
                else:
                    user_basis = "user not available on one side (not compared)"
                anchor = ("process start" if owner.process
                          else "first PowerShell record (no process record)")
                notes.append({
                    "link": kind,
                    "event_id": event.event_id,
                    "evidence_id": event.evidence_id,
                    "basis": ["same device", f"same pid {owner.pid}",
                              f"within {window} s after {anchor}", user_basis],
                })
        return sorted(notes, key=lambda n: n["event_id"])
