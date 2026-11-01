"""IOC extraction (Module 5) - the public entry point.

    from security.ioc import extract_case_iocs
    result = extract_case_iocs("security/sample_evidence/INC-001")
    for ioc in result.iocs:
        print(ioc.ioc_id, ioc.type.value, ioc.value, ioc.related_findings)

SCOPE: only evidence that a finding cites is examined. An event is "cited"
when it is one of the finding's ``supporting_events`` or one of the records the
finding's ``context.correlated_records`` lists (same device, PID and time
window). Benign traffic that no finding mentions never becomes an IOC. One
extra link exists: a ``file_created`` record (files.json) is added when its
path equals the path of an extracted filename IOC (exact match after
normalization), and it brings its hash.

WHAT IS EXTRACTED (each value is validated, never accepted because it merely
matches a pattern):

ip        logon source addresses, remote addresses of connections, valid IPv4
          addresses in command/script text and URL hosts. Classified with the
          detection IP policy; only ``ip_classes`` are kept.
domain    ``remote_hostname`` of connections and the host of URLs.
url       http/https/ftp URLs in command lines, script text and decoded
          -EncodedCommand text (credentials removed).
filename  file paths with a suspicious extension outside protected Windows
          folders (the IOC value is the file name; full paths are kept).
hash      sha256/sha1/md5 of files linked by path and of non-system processes.
process   executables outside protected folders, or unknown names without a path.
username  accounts that acted, were created or were added to a group.

Each IOC is unique per (type, value), keeps EVERY occurrence with its record,
field and time, and lists the findings it relates to. Nothing is modified or
written; the result is deterministic.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional, Union

from security.detection import DetectionConfig, run_detection
from security.detection.base import format_ids
from security.detection.ip_policy import IpClass, classify_ip
from security.ioc import parsers
from security.ioc.config import IocConfig
from security.models.schemas import (
    IOC, DetectionResult, EventType, IocResult, IOCType, Timeline, TimelineEntry)
from security.timeline import build_case_timeline
from security.utils.helpers import format_timestamp

_TYPE_RANK = {ioc_type: rank for rank, ioc_type in enumerate(IOCType)}


@dataclass
class _Candidate:
    type: IOCType
    key: str                     # de-duplication key (normalized)
    value: str                   # value as shown
    entry: TimelineEntry
    field: str
    role: str                    # human-readable role of this occurrence
    extra: dict[str, Any] = field(default_factory=dict)
    inherited: tuple[str, ...] = ()   # findings inherited through a path link


def cited_event_ids(finding: Any) -> list[str]:
    """Event ids a finding cites: supporting events + correlated records."""
    ids = list(finding.supporting_events)
    for record in finding.context.get("correlated_records", []):
        event_id = record.get("event_id")
        if event_id and event_id not in ids:
            ids.append(event_id)
    return ids


class _Collector:
    """Turns timeline entries into validated candidates."""

    def __init__(self, config: IocConfig, gaps: set[str]) -> None:
        self.cfg = config
        self.gaps = gaps
        self.candidates: list[_Candidate] = []
        self.process_without_path: list[str] = []

    def add(self, ioc_type: IOCType, key: str, value: str, entry: TimelineEntry,
            field_name: str, role: str, inherited: tuple[str, ...] = (),
            **extra: Any) -> None:
        self.candidates.append(_Candidate(ioc_type, key, value, entry, field_name, role,
                                          extra, inherited))

    # ------------------------------------------------------- value helpers
    def ip(self, entry: TimelineEntry, field_name: str, raw: Any, role: str,
           structured: bool, **extra: Any) -> None:
        ip_class = classify_ip(raw)
        if ip_class is IpClass.MISSING:
            return
        if ip_class is IpClass.INVALID:
            if structured:
                self.gaps.add(f"{entry.evidence_id}: {field_name} {raw!r} is not a valid "
                              "IP address; not extracted")
            return
        if ip_class.value not in self.cfg.ip_classes:
            return
        address = parsers.canonical_ip(raw)
        self.add(IOCType.IP, address, address, entry, field_name, role, **extra)

    def domain(self, entry: TimelineEntry, field_name: str, raw: Any, role: str) -> None:
        if raw is None or (isinstance(raw, str) and not raw.strip()):
            return
        host = parsers.normalize_domain(raw)
        if host is None:
            self.gaps.add(f"{entry.evidence_id}: {field_name} {raw!r} is not a valid "
                          "domain name; not extracted")
            return
        self.add(IOCType.DOMAIN, host, host, entry, field_name, role)

    def username(self, entry: TimelineEntry, field_name: str, raw: Any, role: str) -> None:
        if not isinstance(raw, str):
            return
        name = raw.strip()
        if (not name or name.casefold() in self.cfg.ignored_usernames
                or name.endswith("$")):
            return
        self.add(IOCType.USERNAME, name.casefold(), name, entry, field_name, role)

    def path(self, entry: TimelineEntry, field_name: str, path: str, role: str,
             inherited: tuple[str, ...] = ()) -> bool:
        cfg = self.cfg
        if parsers.extension_of(path) not in cfg.suspicious_extensions:
            return False
        if parsers.is_system_path(path, cfg.system_path_prefixes,
                                  cfg.writable_path_fragments):
            return False
        name = parsers.filename_of(path)
        self.add(IOCType.FILENAME, name.casefold(), name, entry, field_name, role,
                 inherited, path=path)
        return True

    def hash(self, entry: TimelineEntry, field_name: str, raw: Any, role: str,
             inherited: tuple[str, ...] = (), **extra: Any) -> None:
        if raw is None or (isinstance(raw, str) and not raw.strip()):
            return
        parsed = parsers.parse_hash(raw)
        if parsed is None:
            self.gaps.add(f"{entry.evidence_id}: {field_name} {str(raw)[:70]!r} is not a "
                          "valid hash; not extracted")
            return
        algorithm, digest = parsed
        self.add(IOCType.HASH, digest, digest, entry, field_name, role, inherited,
                 algorithm=algorithm, **extra)

    def text(self, entry: TimelineEntry, field_name: str, raw: Any) -> None:
        """URLs, IPs and file paths in free text (and decoded -EncodedCommand text)."""
        if not isinstance(raw, str) or not raw.strip():
            return
        text = raw[: self.cfg.max_scan_chars]
        for label, variant in parsers.text_variants(
                text, field_name, self.cfg.decode_encoded_commands):
            for url in parsers.find_urls_in_text(variant, self.cfg.url_schemes):
                self.add(IOCType.URL, url.value, url.value, entry, label,
                         f"URL found in {label}", scheme=url.scheme, host=url.host,
                         host_type=url.host_type,
                         credentials_removed=url.credentials_removed)
                if url.host_type == "domain":
                    self.add(IOCType.DOMAIN, url.host, url.host, entry, label,
                             f"host of a URL found in {label}")
                else:
                    self.ip(entry, label, url.host, f"host of a URL found in {label}", False)
            for address in parsers.find_ipv4_in_text(variant):
                self.ip(entry, label, address, f"address found in the text of {label}",
                        False)
            for path in parsers.find_paths_in_text(variant):
                self.path(entry, label, path, f"file path found in {label}")

    # -------------------------------------------------------- per event
    def collect(self, entry: TimelineEntry) -> None:
        details, kind = entry.details, entry.event_type
        if kind in (EventType.LOGON_FAILED, EventType.LOGON_SUCCESS):
            word = "failed" if kind is EventType.LOGON_FAILED else "successful"
            via = f" ({details['logon_type_name']})" if details.get("logon_type_name") else ""
            self.ip(entry, "source_ip", details.get("source_ip"),
                    f"source address of a {word} logon{via}", True)
            self.username(entry, "user", entry.user, f"account of a {word} logon")
        elif kind is EventType.NETWORK_CONNECTION:
            who = details.get("process_name") or "an unknown process"
            direction = details.get("direction") or "unknown-direction"
            self.ip(entry, "remote_address", details.get("remote_address"),
                    f"remote address of an {direction} connection by {who}", True,
                    port=details.get("remote_port"), direction=details.get("direction"))
            self.domain(entry, "remote_hostname", details.get("remote_hostname"),
                        f"remote host name of a connection by {who}")
            self.username(entry, "user", entry.user, "account associated with a connection")
        elif kind is EventType.PROCESS_CREATED:
            self.text(entry, "command_line", details.get("command_line"))
            self._process(entry)
            self.username(entry, "user", entry.user, "account that started a process")
        elif kind is EventType.POWERSHELL_EXECUTED:
            self.text(entry, "command", details.get("command"))
            self.text(entry, "host_application", details.get("host_application"))
            script = details.get("script_path")
            if isinstance(script, str) and parsers.is_valid_file_path(script.strip()):
                self.path(entry, "script_path", script.strip(),
                          "script path of a PowerShell record")
            self.username(entry, "user", entry.user, "account that ran PowerShell")
        elif kind is EventType.FILE_CREATED:
            self.file_record(entry, linked=False)
            self.username(entry, "user", entry.user, "owner of a created file")
        elif kind is EventType.ACCOUNT_CREATED:
            self.username(entry, "user", entry.user, "account that created an account")
            self.username(entry, "target_user", details.get("target_user"),
                          "account that was created")
        elif kind is EventType.GROUP_MEMBER_ADDED:
            self.username(entry, "user", entry.user,
                          "account that changed a group membership")
            self.username(entry, "member_name", details.get("member_name"),
                          f"account added to group '{details.get('group') or 'unknown'}'")

    def _process(self, entry: TimelineEntry) -> None:
        details, cfg = entry.details, self.cfg
        raw_path, name = details.get("executable_path"), details.get("name")
        has_path = isinstance(raw_path, str) and bool(raw_path.strip())
        basis = None
        if has_path:
            path = raw_path.strip()
            if not parsers.is_system_path(path, cfg.system_path_prefixes,
                                          cfg.writable_path_fragments):
                basis, value, key, field_name = (
                    "executable path outside protected system folders", path,
                    parsers.normalize_path_key(path), "executable_path")
        elif isinstance(name, str) and name.strip():
            self.process_without_path.append(entry.evidence_id)
            if name.strip().casefold() not in cfg.known_system_processes:
                basis, value, key, field_name = (
                    "name not in the known system process list (path unavailable)",
                    name.strip(), name.strip().casefold(), "name")
        if basis is None:
            return
        who = entry.user or "an unknown user"
        self.add(IOCType.PROCESS, key, value, entry, field_name,
                 f"process started by {who}", basis=basis, pid=details.get("pid"))
        self.hash(entry, "sha256", details.get("sha256"), "hash of a process executable",
                  file_path=value if has_path else None)

    def file_record(self, entry: TimelineEntry, linked: bool,
                    inherited: tuple[str, ...] = ()) -> None:
        details = entry.details
        raw_path = details.get("path")
        if not (isinstance(raw_path, str)
                and parsers.is_valid_file_path(raw_path.strip())):
            return
        path = raw_path.strip()
        role = ("file record at a path found in finding evidence" if linked
                else "file created")
        if self.path(entry, "path", path, role, inherited):
            self.hash(entry, "sha256", details.get("sha256"),
                      f"hash of the file {parsers.filename_of(path)}", inherited,
                      file_path=path)


# ------------------------------------------------------------------ public API
def extract_iocs(timeline: Timeline, detection: DetectionResult,
                 config: Optional[IocConfig] = None) -> IocResult:
    """Extract IOCs from the evidence cited by ``detection``'s findings.

    Raises:
        TypeError: wrong argument types.
        ValueError: ``timeline`` and ``detection`` belong to different cases.
    """
    if not isinstance(timeline, Timeline):
        raise TypeError(f"timeline must be a Timeline, got {type(timeline).__name__}")
    if not isinstance(detection, DetectionResult):
        raise TypeError("detection must be a DetectionResult, got "
                        f"{type(detection).__name__}")
    if config is None:
        config = IocConfig()
    elif not isinstance(config, IocConfig):
        raise TypeError(f"config must be an IocConfig, got {type(config).__name__}")
    if timeline.case_id and detection.case_id and timeline.case_id != detection.case_id:
        raise ValueError(f"timeline case {timeline.case_id!r} differs from the detection "
                         f"case {detection.case_id!r}")

    gaps: set[str] = set()
    by_id = {entry.event_id: entry for entry in timeline.entries}

    cited: dict[str, set[str]] = {}
    for finding in detection.findings:
        for event_id in cited_event_ids(finding):
            if event_id in by_id:
                cited.setdefault(event_id, set()).add(finding.finding_id)
            else:
                gaps.add(f"{finding.finding_id} cites event {event_id}, which is not in "
                         "the timeline; it was skipped")

    collector = _Collector(config, gaps)
    for entry in timeline.entries:                       # chronological
        if entry.event_id in cited:
            collector.collect(entry)

    if config.link_file_records:
        _link_file_records(timeline, collector, cited)
    if collector.process_without_path:
        gaps.add(f"{len(collector.process_without_path)} process record(s) cited by "
                 "findings have no executable_path, so they were judged by name only: "
                 f"{format_ids(collector.process_without_path)}")

    iocs = _build_iocs(collector.candidates, cited, config)
    findings = []
    for finding in detection.findings:
        updated = copy.deepcopy(finding)
        updated.iocs = [ioc.ioc_id for ioc in iocs
                        if finding.finding_id in ioc.related_findings]
        findings.append(updated)

    counts: dict[str, int] = {}
    for ioc in iocs:
        counts[ioc.type.value] = counts.get(ioc.type.value, 0) + 1
    return IocResult(case_id=detection.case_id or timeline.case_id, iocs=iocs,
                     findings=findings, counts_by_type=counts,
                     data_gaps=sorted(gaps), config=config.to_dict())


def extract_case_iocs(
    folder: Union[str, Path],
    detection_config: Optional[DetectionConfig] = None,
    ioc_config: Optional[IocConfig] = None,
    now: Any = None,
) -> IocResult:
    """Validate, normalize, build the timeline, detect and extract IOCs for a folder.

    Raises:
        EvidenceNotValidError: the evidence failed validation.
    """
    timeline = build_case_timeline(folder)
    detection = run_detection(timeline, config=detection_config, now=now)
    return extract_iocs(timeline, detection, ioc_config)


# ------------------------------------------------------------------ internals
def _link_file_records(timeline: Timeline, collector: _Collector,
                       cited: dict[str, set[str]]) -> None:
    """Add file records whose path equals an extracted filename IOC's path."""
    path_findings: dict[str, set[str]] = {}
    for candidate in collector.candidates:
        if candidate.type is IOCType.FILENAME and "path" in candidate.extra:
            key = parsers.normalize_path_key(candidate.extra["path"])
            path_findings.setdefault(key, set()).update(
                cited.get(candidate.entry.event_id, ()))
    for entry in timeline.entries:
        if entry.event_type is not EventType.FILE_CREATED or entry.event_id in cited:
            continue
        raw = entry.details.get("path")
        if not isinstance(raw, str):
            continue
        findings = path_findings.get(parsers.normalize_path_key(raw.strip()))
        if findings:
            collector.file_record(entry, linked=True, inherited=tuple(sorted(findings)))


def _attributes(ioc_type: IOCType, value: str, candidates: list[_Candidate],
                config: IocConfig) -> dict[str, Any]:
    first = candidates[0]
    if ioc_type is IOCType.IP:
        return {"ip_class": classify_ip(value).value,
                "external": config.ip_policy.is_external(value)}
    if ioc_type is IOCType.DOMAIN:
        return {"reserved_for_documentation": parsers.is_reserved_domain(value)}
    if ioc_type is IOCType.URL:
        return {"scheme": first.extra["scheme"], "host": first.extra["host"],
                "host_type": first.extra["host_type"],
                "credentials_removed": any(c.extra.get("credentials_removed")
                                           for c in candidates)}
    if ioc_type is IOCType.FILENAME:
        paths: dict[str, str] = {}
        for candidate in candidates:
            paths.setdefault(parsers.normalize_path_key(candidate.extra["path"]),
                             candidate.extra["path"])
        return {"extension": parsers.extension_of(value), "paths": list(paths.values())}
    if ioc_type is IOCType.HASH:
        file_paths = list(dict.fromkeys(
            c.extra["file_path"] for c in candidates if c.extra.get("file_path")))
        return {"algorithm": first.extra["algorithm"], "file_paths": file_paths}
    if ioc_type is IOCType.PROCESS:
        return {"basis": first.extra["basis"]}
    return {"roles": sorted({c.role for c in candidates})}


def _occurrence(candidate: _Candidate) -> dict[str, Any]:
    entry = candidate.entry
    occurrence: dict[str, Any] = {
        "event_id": entry.event_id,
        "evidence_id": entry.evidence_id,
        "evidence_file": entry.evidence_file,
        "field": candidate.field,
        "timestamp": format_timestamp(entry.timestamp),
        "context": candidate.role,
    }
    for name in ("path", "port", "direction", "pid"):
        if candidate.extra.get(name) is not None:
            occurrence[name] = candidate.extra[name]
    return occurrence


def _build_iocs(candidates: list[_Candidate], cited: dict[str, set[str]],
                config: IocConfig) -> list[IOC]:
    groups: dict[tuple[IOCType, str], list[_Candidate]] = {}
    for candidate in candidates:
        groups.setdefault((candidate.type, candidate.key), []).append(candidate)

    drafts = []
    for (ioc_type, key), members in groups.items():
        members.sort(key=lambda c: (c.entry.sequence, c.field, c.extra.get("path") or ""))
        unique: dict[tuple, _Candidate] = {}
        for member in members:                           # one occurrence per place
            unique.setdefault((member.entry.event_id, member.field,
                               member.extra.get("path") or ""), member)
        ordered = list(unique.values())
        findings: set[str] = set()
        for member in ordered:
            findings |= cited.get(member.entry.event_id, set())
            findings |= set(member.inherited)
        drafts.append((ioc_type, key, ordered, sorted(findings)))

    drafts.sort(key=lambda d: (d[2][0].entry.timestamp, _TYPE_RANK[d[0]], d[1]))
    iocs: list[IOC] = []
    for number, (ioc_type, key, ordered, findings) in enumerate(drafts, start=1):
        primary = ordered[0]
        stamps = [c.entry.timestamp for c in ordered]
        context = primary.role + (f" (+{len(ordered) - 1} more occurrence(s))"
                                  if len(ordered) > 1 else "")
        iocs.append(IOC(
            ioc_id=f"IOC-{number:03d}", type=ioc_type, value=primary.value,
            source=primary.entry.evidence_file, evidence_id=primary.entry.evidence_id,
            timestamp=min(stamps), context=context, related_findings=findings,
            first_seen=min(stamps), last_seen=max(stamps),
            attributes=_attributes(ioc_type, primary.value, ordered, config),
            occurrences=[_occurrence(c) for c in ordered]))
    return iocs
