"""Shared data contracts for the Sentinel DFIR analysis module.

Two kinds of definitions live here:

1. **Evidence contract constants** - what the Windows collector must deliver
   (file names, required record fields, ID prefixes). The Phase 2 validator
   reads these so the contract has a single source of truth.
2. **Output schemas** - plain ``dataclasses`` produced by the analysis
   pipeline (normalized events, IOCs, MITRE mappings, findings, and the final
   investigation result). Each has ``to_dict()`` so the backend can store it in
   SQL or return it from FastAPI without any extra work.

Only the standard library is used on purpose. The backend can wrap these in
Pydantic models later without touching analysis logic.
"""

from __future__ import annotations

from dataclasses import dataclass, field, fields, is_dataclass
from datetime import datetime
from enum import Enum
from typing import Any, ClassVar, Optional

from security.utils.helpers import format_timestamp

SCHEMA_VERSION = "1.0"


# --------------------------------------------------------------------------
# 1. Evidence contract (Windows collector -> analysis module)
# --------------------------------------------------------------------------
class EvidenceSource(str, Enum):
    """The evidence files a collector can deliver (``<value>.json``)."""

    SYSTEM = "system"
    PROCESSES = "processes"
    NETWORK = "network"
    USERS = "users"
    EVENTS = "events"
    POWERSHELL = "powershell"
    FILES = "files"


MANIFEST_FILENAME = "manifest.json"

# MVP: these six must be present. files.json is optional (validator warns).
REQUIRED_SOURCES: tuple[EvidenceSource, ...] = (
    EvidenceSource.SYSTEM,
    EvidenceSource.PROCESSES,
    EvidenceSource.NETWORK,
    EvidenceSource.USERS,
    EvidenceSource.EVENTS,
    EvidenceSource.POWERSHELL,
)
OPTIONAL_SOURCES: tuple[EvidenceSource, ...] = (EvidenceSource.FILES,)

# Every evidence file is wrapped in this envelope.
ENVELOPE_FIELDS: tuple[str, ...] = (
    "schema_version",
    "case_id",
    "device",
    "source",
    "collected_at",
    "collector",
    "records",
)

# record_id prefix per source, e.g. PROC-0001. IDs are unique within a case
# and are how findings point back to raw evidence.
RECORD_ID_PREFIX: dict[EvidenceSource, str] = {
    EvidenceSource.SYSTEM: "SYS",
    EvidenceSource.PROCESSES: "PROC",
    EvidenceSource.NETWORK: "NET",
    EvidenceSource.USERS: "USR",
    EvidenceSource.EVENTS: "EVL",
    EvidenceSource.POWERSHELL: "PS",
    EvidenceSource.FILES: "FILE",
}

# Fields every record of a given source must contain (Phase 2 enforces this).
# Extra fields are allowed and ignored, so the collector can add data without
# breaking the analysis engine.
REQUIRED_RECORD_FIELDS: dict[EvidenceSource, tuple[str, ...]] = {
    EvidenceSource.SYSTEM: (
        "record_id", "hostname", "os_name", "os_version", "architecture",
        "boot_time",
    ),
    EvidenceSource.PROCESSES: (
        "record_id", "timestamp", "pid", "ppid", "name", "command_line", "user",
    ),
    EvidenceSource.NETWORK: (
        "record_id", "timestamp", "protocol", "local_address", "local_port",
        "remote_address", "remote_port", "direction", "pid", "process_name",
    ),
    EvidenceSource.USERS: (
        "record_id", "username", "account_type", "enabled", "is_admin",
        "created_at",
    ),
    EvidenceSource.EVENTS: (
        "record_id", "timestamp", "event_id", "channel", "provider", "data",
    ),
    EvidenceSource.POWERSHELL: (
        "record_id", "timestamp", "user", "pid", "command",
    ),
    EvidenceSource.FILES: (
        "record_id", "timestamp", "path", "name", "size_bytes", "sha256",
    ),
}

# Required fields whose VALUE may be null. "Required" still means the key must
# be present in every record; null is accepted only where the collector can
# genuinely fail to retrieve the value. Every other required field must be
# non-null. Keep this list minimal and document each entry in
# docs/EVIDENCE_CONTRACT.md (section 2, "Missing values").
NULLABLE_REQUIRED_FIELDS: dict[EvidenceSource, tuple[str, ...]] = {
    # Protected/system processes can hide their command line from the collector.
    EvidenceSource.PROCESSES: ("command_line",),
}

# Type names used below (checked by the Phase 2 validator):
#   str, int, bool, object (JSON object), list_str (list of strings),
#   ts (UTC ISO 8601 ending in 'Z'), ipv4 (IPv4 string),
#   sha256 (64 lowercase hex characters)
ENVELOPE_FIELD_TYPES: dict[str, str] = {
    "schema_version": "str",
    "case_id": "str",
    "device": "str",
    "source": "str",
    "collected_at": "ts",
    "collector": "object",
    "records": "list",
}

# Every field the contract defines per source (required AND optional) with
# its type. Transcribed from docs/EVIDENCE_CONTRACT.md section 4; keep the two
# in sync. Fields not listed here are "extra fields" and are ignored.
FIELD_TYPES: dict[EvidenceSource, dict[str, str]] = {
    EvidenceSource.SYSTEM: {
        "record_id": "str", "hostname": "str", "os_name": "str",
        "os_version": "str", "architecture": "str", "boot_time": "ts",
        "domain": "str", "timezone": "str", "utc_offset_minutes": "int",
        "ip_addresses": "list_str",
    },
    EvidenceSource.PROCESSES: {
        "record_id": "str", "timestamp": "ts", "pid": "int", "ppid": "int",
        "name": "str", "command_line": "str", "user": "str",
        "parent_name": "str", "executable_path": "str", "sha256": "str",
        "origin": "str",
    },
    EvidenceSource.NETWORK: {
        "record_id": "str", "timestamp": "ts", "protocol": "str",
        "local_address": "ipv4", "local_port": "int",
        "remote_address": "ipv4", "remote_port": "int", "direction": "str",
        "pid": "int", "process_name": "str", "state": "str",
        "remote_hostname": "str", "user": "str", "origin": "str",
    },
    EvidenceSource.USERS: {
        "record_id": "str", "username": "str", "account_type": "str",
        "enabled": "bool", "is_admin": "bool", "created_at": "ts",
        "sid": "str", "groups": "list_str", "last_logon": "ts",
    },
    EvidenceSource.EVENTS: {
        "record_id": "str", "timestamp": "ts", "event_id": "int",
        "channel": "str", "provider": "str", "data": "object",
        "record_number": "int", "keywords": "str",
    },
    EvidenceSource.POWERSHELL: {
        "record_id": "str", "timestamp": "ts", "user": "str", "pid": "int",
        "command": "str", "event_id": "int", "log": "str", "origin": "str",
        "script_path": "str", "host_application": "str",
    },
    EvidenceSource.FILES: {
        "record_id": "str", "timestamp": "ts", "path": "str", "name": "str",
        "size_bytes": "int", "sha256": "sha256", "modified_at": "ts",
        "owner": "str",
    },
}

# Closed value sets the contract spells out ("`TCP` / `UDP`", ...).
FIELD_ALLOWED_VALUES: dict[EvidenceSource, dict[str, tuple[str, ...]]] = {
    EvidenceSource.PROCESSES: {"origin": ("event_log", "live_snapshot")},
    EvidenceSource.NETWORK: {
        "protocol": ("TCP", "UDP"),
        "direction": ("inbound", "outbound"),
        "origin": ("event_log", "live_snapshot"),
    },
    EvidenceSource.USERS: {"account_type": ("local", "domain")},
    EvidenceSource.POWERSHELL: {
        "origin": ("script_block_log", "psreadline_history"),
    },
}


# --------------------------------------------------------------------------
# 2. Controlled vocabularies
# --------------------------------------------------------------------------
class EventType(str, Enum):
    """Normalized event types. Add new values here, never ad-hoc strings."""

    LOGON_SUCCESS = "logon_success"
    LOGON_FAILED = "logon_failed"
    PROCESS_CREATED = "process_created"
    NETWORK_CONNECTION = "network_connection"
    POWERSHELL_EXECUTED = "powershell_executed"
    ACCOUNT_CREATED = "account_created"
    GROUP_MEMBER_ADDED = "group_member_added"
    FILE_CREATED = "file_created"
    OTHER = "other"


class Severity(str, Enum):
    INFO = "Info"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class Confidence(str, Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"


class IOCType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH = "hash"
    FILENAME = "filename"
    PROCESS = "process"
    USERNAME = "username"


# --------------------------------------------------------------------------
# 3. Serialization helper
# --------------------------------------------------------------------------
def to_plain(value: Any) -> Any:
    """Recursively convert dataclasses/enums/datetimes into JSON-safe types."""
    if is_dataclass(value) and not isinstance(value, type):
        # DERIVED_FIELDS names read-only properties (e.g. ValidationResult.valid)
        # that must appear in the output at any nesting depth, listed first.
        derived = {name: to_plain(getattr(value, name))
                   for name in getattr(value, "DERIVED_FIELDS", ())}
        return {**derived,
                **{f.name: to_plain(getattr(value, f.name)) for f in fields(value)}}
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime):
        return format_timestamp(value)
    if isinstance(value, (list, tuple)):
        return [to_plain(item) for item in value]
    if isinstance(value, dict):
        return {key: to_plain(item) for key, item in value.items()}
    return value


class _Serializable:
    """Mixin giving each schema a ``to_dict()`` method."""

    def to_dict(self) -> dict[str, Any]:
        return to_plain(self)


# --------------------------------------------------------------------------
# 4. Output schemas
# --------------------------------------------------------------------------
@dataclass
class NormalizedEvent(_Serializable):
    """One event in the common representation (SQL table: TimelineEvents).

    ``evidence_id`` is the ``record_id`` of the raw record this event came
    from, so every timeline row can be traced back to a collector file.
    """

    event_id: str                      # e.g. "E-00012" (assigned after sorting)
    case_id: str
    timestamp: datetime                # timezone-aware, UTC
    event_type: EventType
    source: EvidenceSource
    device: str
    user: Optional[str]
    evidence_id: str                   # e.g. "EVL-0007"
    details: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.event_type = EventType(self.event_type)
        self.source = EvidenceSource(self.source)
        if self.timestamp.tzinfo is None:
            raise ValueError("NormalizedEvent.timestamp must be timezone-aware")

    @property
    def evidence_file(self) -> str:
        return f"{self.source.value}.json"


@dataclass
class IOC(_Serializable):
    """An indicator of compromise with its origin (SQL table: IOCs).

    One IOC per unique (type, value) in a case. ``source`` / ``evidence_id`` /
    ``timestamp`` describe its EARLIEST occurrence; every place it appeared is
    listed in ``occurrences`` (added in Phase 6, optional), so nothing is lost
    when the same value shows up in several records.
    """

    ioc_id: str                        # e.g. "IOC-001"
    type: IOCType
    value: str
    source: str                        # evidence file, e.g. "network.json"
    evidence_id: str                   # e.g. "NET-0004"
    timestamp: Optional[datetime] = None
    context: str = ""                  # short human-readable note
    related_findings: list[str] = field(default_factory=list)
    # Added in Phase 6 (all optional, so earlier code keeps working):
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    attributes: dict[str, Any] = field(default_factory=dict)       # type-specific facts
    occurrences: list[dict[str, Any]] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.type = IOCType(self.type)


@dataclass
class MitreMapping(_Serializable):
    """A possible ATT&CK technique linked to finding(s) (MITRE_Techniques).

    ``technique_id`` is the MOST SPECIFIC mapped id (``T1059.001`` for a
    sub-technique, ``T1105`` for a technique) and ``technique_name`` its full
    ATT&CK display name (``Command and Scripting Interpreter: PowerShell``).
    For sub-technique mappings the parent technique and the sub-technique are
    also given separately. ``tactic`` / ``tactic_id`` are the ONE tactic the
    evidence supports; ``tactics`` lists all tactics ATT&CK assigns to the
    technique. ``reason`` must use cautious wording ("consistent with"): an
    observation never proves a technique by itself.

    Fields after ``reason`` were added in Phase 7 (all optional, so earlier
    code keeps working). ``related_finding`` stays the first source finding.
    """

    technique_id: str                  # "T1059.001"
    technique_name: str                # "Command and Scripting Interpreter: PowerShell"
    tactic: str                        # "Execution"
    related_finding: str               # "F-001" (first source finding)
    reason: str
    mapping_id: str = ""               # "MAP-T1059.001-TA0002"
    tactic_id: str = ""                # "TA0002"
    tactics: list[dict[str, str]] = field(default_factory=list)   # [{"id","name"}]
    is_subtechnique: bool = False
    parent_technique_id: Optional[str] = None        # "T1059"
    parent_technique_name: Optional[str] = None      # "Command and Scripting Interpreter"
    subtechnique_id: Optional[str] = None            # "T1059.001"
    subtechnique_name: Optional[str] = None          # "PowerShell"
    related_findings: list[str] = field(default_factory=list)
    supporting_events: list[str] = field(default_factory=list)
    evidence_sources: list[str] = field(default_factory=list)    # raw record ids
    ioc_ids: list[str] = field(default_factory=list)
    confidence: Optional[Confidence] = None
    confidence_factors: list[str] = field(default_factory=list)
    sources: list[dict[str, Any]] = field(default_factory=list)  # per-finding detail
    attack_version: str = ""                         # "19.2"

    def __post_init__(self) -> None:
        if self.confidence is not None:
            self.confidence = Confidence(self.confidence)


@dataclass
class Finding(_Serializable):
    """A detection result after correlation (SQL table: Findings).

    List fields hold IDs, not embedded objects, so SQL can link rows:
    ``supporting_events`` -> event_id, ``evidence_sources`` -> record_id,
    ``iocs`` -> ioc_id, ``mitre_techniques`` -> technique_id.
    """

    finding_id: str                    # "F-001"
    rule_id: str                       # "DET-002"
    title: str
    severity: Severity
    confidence: Confidence
    device: str
    user: Optional[str]
    description: str
    reason: str                        # why the rule fired (explainability)
    detected_at: datetime              # when the analysis produced it
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    supporting_events: list[str] = field(default_factory=list)
    evidence_sources: list[str] = field(default_factory=list)
    iocs: list[str] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)
    severity_factors: list[str] = field(default_factory=list)
    confidence_factors: list[str] = field(default_factory=list)
    recommended_next_steps: list[str] = field(default_factory=list)
    # Added in Phase 5 (all optional, so earlier code keeps working):
    rule_name: str = ""
    evidence_files: list[str] = field(default_factory=list)     # e.g. "events.json"
    matched_indicators: list[dict[str, Any]] = field(default_factory=list)
    context: dict[str, Any] = field(default_factory=dict)       # grouping, thresholds,
    #                                                             correlation, data gaps

    def __post_init__(self) -> None:
        self.severity = Severity(self.severity)
        self.confidence = Confidence(self.confidence)


@dataclass
class InvestigationResult(_Serializable):
    """Everything the backend, frontend, AI assistant and report need.

    SQL mapping: header -> Incidents, ``evidence_files`` -> Evidence,
    ``timeline`` -> TimelineEvents, ``findings`` -> Findings,
    ``iocs`` -> IOCs, ``mitre_mappings`` -> MITRE_Techniques.
    """

    incident_id: str                   # same as the evidence case_id
    device: str
    generated_at: datetime
    schema_version: str = SCHEMA_VERSION
    time_start: Optional[datetime] = None
    time_end: Optional[datetime] = None
    users_involved: list[str] = field(default_factory=list)
    evidence_files: list[dict[str, Any]] = field(default_factory=list)
    timeline: list[NormalizedEvent] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    iocs: list[IOC] = field(default_factory=list)
    mitre_mappings: list[MitreMapping] = field(default_factory=list)
    # Phase 8 additive fields: keep the original contract backwards-compatible.
    summary: str = ""
    finding_assessments: list[dict[str, Any]] = field(default_factory=list)
    finding_links: list[dict[str, Any]] = field(default_factory=list)
    data_gaps: list[str] = field(default_factory=list)
    provenance_check: dict[str, Any] = field(default_factory=dict)
    evidence_integrity: list[dict[str, Any]] = field(default_factory=list)


# --------------------------------------------------------------------------
# 5. Validation result schemas (Phase 2)
# --------------------------------------------------------------------------
class IssueSeverity(str, Enum):
    ERROR = "error"        # evidence must not be analyzed
    WARNING = "warning"    # evidence is usable, but something is worth knowing


@dataclass
class ValidationIssue(_Serializable):
    """One problem found in the evidence.

    ``code`` is a stable machine-readable identifier (e.g. ``FIELD_MISSING``);
    ``message`` is a complete human-readable sentence that already names the
    file, record and field involved.
    """

    code: str
    severity: IssueSeverity
    message: str
    file: Optional[str] = None
    record_id: Optional[str] = None
    field: Optional[str] = None

    def __post_init__(self) -> None:
        self.severity = IssueSeverity(self.severity)


@dataclass
class ValidationResult(_Serializable):
    """Outcome of validating one evidence folder.

    ``valid`` is derived: it is True only when there are no errors.
    Warnings never make a case invalid.
    """

    DERIVED_FIELDS: ClassVar[tuple[str, ...]] = ("valid",)

    folder: str
    case_id: Optional[str] = None
    device: Optional[str] = None
    checked_files: list[str] = field(default_factory=list)
    errors: list[ValidationIssue] = field(default_factory=list)
    warnings: list[ValidationIssue] = field(default_factory=list)

    @property
    def valid(self) -> bool:
        return not self.errors

    def add(self, issue: ValidationIssue) -> None:
        """File an issue under errors or warnings according to its severity."""
        target = (
            self.errors if issue.severity is IssueSeverity.ERROR else self.warnings
        )
        target.append(issue)


# --------------------------------------------------------------------------
# 6. Normalization result schemas (Phase 3)
# --------------------------------------------------------------------------
@dataclass
class NormalizationWarning(_Serializable):
    """A data-quality note raised while normalizing one record.

    Normalization never drops a record because of these; the event is still
    produced, with the affected value set to ``None``.
    """

    code: str                          # e.g. "EVENT_DATA_MISSING_FIELD"
    message: str
    source: EvidenceSource
    evidence_id: str                   # record_id the note is about

    def __post_init__(self) -> None:
        self.source = EvidenceSource(self.source)


@dataclass
class NormalizationResult(_Serializable):
    """Output of the normalization stage.

    * ``events``  - the timeline events, in deterministic chronological order
      with sequential ``event_id`` values.
    * ``host``    - system.json content: host CONTEXT, never a timeline event.
    * ``users``   - users.json content: account snapshot used for ENRICHMENT
      (also never timeline events).
    * ``validation`` - the validation result the events were produced from
      (kept so warnings such as a missing optional file travel with the data).
    """

    case_id: str
    device: str
    events: list[NormalizedEvent] = field(default_factory=list)
    host: dict[str, Any] = field(default_factory=dict)
    users: list[dict[str, Any]] = field(default_factory=list)
    source_counts: dict[str, int] = field(default_factory=dict)
    warnings: list[NormalizationWarning] = field(default_factory=list)
    validation: Optional[ValidationResult] = None


# --------------------------------------------------------------------------
# 7. Timeline schemas (Phase 4)
# --------------------------------------------------------------------------
@dataclass
class TimelineEntry(_Serializable):
    """One row of the incident timeline (SQL table: TimelineEvents).

    Carries EVERY field of the ``NormalizedEvent`` it was built from (so
    nothing is lost) plus presentation/sequence data. ``event_id`` and
    ``evidence_id`` are the stable keys: they never change when a timeline is
    filtered. ``sequence``, the gap and the offset belong to the timeline
    the entry currently sits in (a filtered timeline renumbers them).
    """

    sequence: int                      # 1-based position in THIS timeline
    event_id: str                      # "E-00012"
    case_id: str
    timestamp: datetime                # timezone-aware, UTC
    event_type: EventType
    source: EvidenceSource
    device: str
    user: Optional[str]
    evidence_id: str                   # raw record_id, e.g. "PROC-0006"
    evidence_file: str                 # raw file, e.g. "processes.json"
    summary: str                       # neutral one-line description of the facts
    gap_from_previous_seconds: Optional[float]   # None for the first entry
    offset_from_start_seconds: float             # 0.0 for the first entry
    details: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.event_type = EventType(self.event_type)
        self.source = EvidenceSource(self.source)
        if self.timestamp.tzinfo is None:
            raise ValueError("TimelineEntry.timestamp must be timezone-aware")

    def to_event(self) -> NormalizedEvent:
        """Rebuild the original ``NormalizedEvent`` (lossless round trip)."""
        return NormalizedEvent(
            event_id=self.event_id, case_id=self.case_id,
            timestamp=self.timestamp, event_type=self.event_type,
            source=self.source, device=self.device, user=self.user,
            evidence_id=self.evidence_id, details=dict(self.details))


@dataclass
class Timeline(_Serializable):
    """A chronological incident timeline (possibly filtered, possibly empty).

    ``start``/``end`` are None and ``duration_seconds`` is 0.0 when empty.
    ``case_id`` is None only for an empty timeline built without one.
    """

    case_id: Optional[str]
    devices: list[str]
    start: Optional[datetime]
    end: Optional[datetime]
    duration_seconds: float
    event_count: int
    counts_by_type: dict[str, int]
    counts_by_source: dict[str, int]
    users: list[str]
    entries: list[TimelineEntry] = field(default_factory=list)

    def get_by_event_id(self, event_id: str) -> Optional[TimelineEntry]:
        """Entry with this ``event_id`` (``E-00012``), or None."""
        return next((e for e in self.entries if e.event_id == event_id), None)

    def get_by_evidence_id(self, evidence_id: str) -> Optional[TimelineEntry]:
        """Entry built from this raw ``record_id`` (``PROC-0006``), or None."""
        return next((e for e in self.entries if e.evidence_id == evidence_id), None)


# --------------------------------------------------------------------------
# 8. Detection result schemas (Phase 5)
# --------------------------------------------------------------------------
@dataclass
class RuleRunSummary(_Serializable):
    """What one rule looked at, so "no finding" is never ambiguous.

    ``events_considered`` is how many events the rule examined and
    ``data_gaps`` lists what it could NOT evaluate because a needed value was
    missing. A rule with 0 findings and no gaps is a real negative result; a
    rule with 0 findings and gaps may have missed something.
    """

    rule_id: str
    rule_name: str
    events_considered: int
    findings: int
    data_gaps: list[str] = field(default_factory=list)


@dataclass
class DetectionResult(_Serializable):
    """Output of the detection stage.

    ``generated_at`` is the analysis time (also each finding's
    ``detected_at``). It is the only value that differs between two runs on
    the same evidence unless the caller supplies ``now``.
    """

    case_id: Optional[str]
    generated_at: datetime
    event_count: int
    config: dict[str, Any]
    rules: list[RuleRunSummary] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    duplicates_removed: int = 0


# --------------------------------------------------------------------------
# 9. IOC extraction result schema (Phase 6)
# --------------------------------------------------------------------------
@dataclass
class IocResult(_Serializable):
    """Output of the IOC extraction stage.

    ``findings`` are COPIES of the detection findings with ``iocs`` filled in
    (ids of the IOCs extracted from their evidence); the input findings are
    never modified. ``data_gaps`` lists values that could not be extracted
    because they were invalid or missing, so a missing IOC is never silently
    mistaken for "there was none".
    """

    case_id: Optional[str]
    iocs: list[IOC] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    counts_by_type: dict[str, int] = field(default_factory=dict)
    data_gaps: list[str] = field(default_factory=list)
    config: dict[str, Any] = field(default_factory=dict)


# --------------------------------------------------------------------------
# 10. ATT&CK mapping result schemas (Phase 7)
# --------------------------------------------------------------------------
@dataclass
class MappingEvaluation(_Serializable):
    """What happened when one mapping rule was applied to one finding.

    ``status`` is one of: ``mapped``; ``not_mapped`` (the conditions were
    evaluated and do not hold); ``not_evaluable`` (needed data was missing, so
    nothing can be said); ``no_rules`` (no mapping is defined for the finding's
    detection rule); ``duplicate`` (the same technique and tactic was already
    mapped for this finding by another rule). ``not_mapped`` and
    ``not_evaluable`` are different: the first is a negative result, the
    second is "unknown".
    """

    finding_id: str
    rule_id: str
    mapping_rule_id: Optional[str]
    technique_id: Optional[str]
    status: str
    reason: str


@dataclass
class MitreResult(_Serializable):
    """Output of the ATT&CK mapping stage.

    ``findings`` are COPIES of the input findings with ``mitre_techniques``
    filled in (technique ids); the inputs are never modified. ``dataset``
    identifies the ATT&CK data used (version, source, hash, retrieval time).
    """

    case_id: Optional[str]
    dataset: dict[str, Any]
    mapping_definition: dict[str, Any]
    mappings: list[MitreMapping] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    evaluations: list[MappingEvaluation] = field(default_factory=list)
    data_gaps: list[str] = field(default_factory=list)
