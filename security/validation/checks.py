"""Contract checks for ONE evidence file (envelope + records).

Every function is pure: it receives parsed data and returns a list of
``ValidationIssue``. It never touches the disk, so each rule is easy to unit
test. The rules come from ``docs/EVIDENCE_CONTRACT.md``; the constants they
use live in ``security/models/schemas.py``.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any, Optional

from security.models.schemas import (
    ENVELOPE_FIELD_TYPES,
    ENVELOPE_FIELDS,
    FIELD_ALLOWED_VALUES,
    FIELD_TYPES,
    NULLABLE_REQUIRED_FIELDS,
    RECORD_ID_PREFIX,
    REQUIRED_RECORD_FIELDS,
    SCHEMA_VERSION,
    EvidenceSource,
    IssueSeverity,
    ValidationIssue,
)
from security.utils.helpers import parse_timestamp

# Contract: ISO 8601, UTC, trailing 'Z'. Fractional seconds are optional
# (Windows writes up to 7 digits); offsets such as +03:00 are NOT accepted.
_TIMESTAMP_FORMAT = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?Z$"
)
_SHA256_FORMAT = re.compile(r"^[0-9a-f]{64}$")
_VERSION_FORMAT = re.compile(r"^(\d+)\.(\d+)$")

_EXPECTED = {
    "str": "a string",
    "int": "an integer",
    "bool": "true or false",
    "object": "a JSON object",
    "list": "a list",
    "list_str": "a list of strings",
    "ipv4": "an IPv4 address string such as '10.20.0.15'",
    "sha256": "64 lowercase hex characters",
}
TIMESTAMP_EXPECTED = "a UTC timestamp ending in 'Z', e.g. 2026-10-08T07:34:01Z"


# ------------------------------------------------------------ value checks
def is_contract_timestamp(value: Any) -> bool:
    """True only for real calendar timestamps in the agreed UTC ``Z`` format."""
    if not isinstance(value, str) or not _TIMESTAMP_FORMAT.match(value):
        return False
    try:
        parse_timestamp(value)
    except ValueError:  # e.g. month 13, day 40, hour 25
        return False
    return True


def type_problem(value: Any, type_name: str) -> Optional[str]:
    """Return a description of what is wrong with ``value``, or None if OK."""
    if type_name == "ts":
        ok = is_contract_timestamp(value)
    elif type_name == "str":
        ok = isinstance(value, str)
    elif type_name == "int":
        ok = isinstance(value, int) and not isinstance(value, bool)
    elif type_name == "bool":
        ok = isinstance(value, bool)
    elif type_name == "object":
        ok = isinstance(value, dict)
    elif type_name == "list":
        ok = isinstance(value, list)
    elif type_name == "list_str":
        ok = isinstance(value, list) and all(isinstance(v, str) for v in value)
    elif type_name == "ipv4":
        ok = isinstance(value, str) and _is_ipv4(value)
    elif type_name == "sha256":
        ok = isinstance(value, str) and bool(_SHA256_FORMAT.match(value))
    else:  # programming error, not bad evidence
        raise ValueError(f"unknown contract type {type_name!r}")
    if ok:
        return None
    expected = TIMESTAMP_EXPECTED if type_name == "ts" else _EXPECTED[type_name]
    return f"must be {expected}, got {_describe(value)}"


def _is_ipv4(value: str) -> bool:
    try:
        ipaddress.IPv4Address(value)
    except ValueError:
        return False
    return True


def _describe(value: Any) -> str:
    text = repr(value)
    if len(text) > 60:
        text = text[:57] + "..."
    return f"{type(value).__name__} {text}"


def _issue(
    code: str,
    message: str,
    file: str,
    record_id: Optional[str] = None,
    field: Optional[str] = None,
    severity: IssueSeverity = IssueSeverity.ERROR,
) -> ValidationIssue:
    return ValidationIssue(code, severity, message, file, record_id, field)


def check_field(
    file: str,
    where: str,
    name: str,
    value: Any,
    type_name: str,
    required: bool,
    record_id: Optional[str] = None,
    nullable: bool = False,
) -> list[ValidationIssue]:
    """Check one present field: null, empty string, then type.

    ``where`` is the text used to point at the place (``"PROC-0003"``,
    ``"envelope"``). Optional fields may be ``null``. Required fields may not,
    unless they are listed in ``NULLABLE_REQUIRED_FIELDS`` (``nullable=True``):
    the key must still be present, only its value may be null. An empty
    string is never accepted in place of null.
    """
    prefix = f"{file} {where}: field '{name}'"
    if value is None:
        if not required or nullable:
            return []
        return [_issue("FIELD_NULL", f"{prefix} is required but is null.",
                       file, record_id, name)]
    if isinstance(value, str) and not value.strip():
        severity = IssueSeverity.ERROR if required else IssueSeverity.WARNING
        return [_issue(
            "FIELD_EMPTY",
            f"{prefix} is an empty string; the contract requires null for "
            "missing values.",
            file, record_id, name, severity,
        )]
    problem = type_problem(value, type_name)
    if problem is None:
        return []
    code = "TIMESTAMP_INVALID" if type_name == "ts" else "FIELD_TYPE"
    return [_issue(code, f"{prefix} {problem}.", file, record_id, name)]


# ---------------------------------------------------------------- envelope
def check_envelope(
    file: str, data: dict[str, Any], source: EvidenceSource
) -> list[ValidationIssue]:
    """Validate the envelope shared by every evidence file."""
    issues: list[ValidationIssue] = []
    for name in ENVELOPE_FIELDS:
        if name not in data:
            issues.append(_issue(
                "ENVELOPE_FIELD_MISSING",
                f"{file}: envelope field '{name}' is missing.",
                file, field=name))
            continue
        if name == "records" and data[name] is not None:
            continue  # shape of 'records' is checked in check_records()
        issues += check_field(
            file, "envelope", name, data[name], ENVELOPE_FIELD_TYPES[name], True
        )

    declared = data.get("source")
    if isinstance(declared, str) and declared != source.value:
        issues.append(_issue(
            "SOURCE_MISMATCH",
            f"{file}: envelope 'source' is {declared!r} but the file name says "
            f"{source.value!r}.",
            file, field="source"))

    if isinstance(data.get("schema_version"), str):
        issues += check_schema_version(file, data["schema_version"])
    return issues


def check_schema_version(file: str, version: str) -> list[ValidationIssue]:
    """Major must match (breaking changes); a newer minor is only a warning."""
    match = _VERSION_FORMAT.match(version)
    if not match:
        return [_issue(
            "SCHEMA_VERSION_INVALID",
            f"{file}: schema_version {version!r} must look like 'MAJOR.MINOR', "
            "e.g. '1.0'.",
            file, field="schema_version")]
    supported_major, supported_minor = (int(p) for p in SCHEMA_VERSION.split("."))
    major, minor = int(match.group(1)), int(match.group(2))
    if major != supported_major:
        return [_issue(
            "SCHEMA_VERSION_UNSUPPORTED",
            f"{file}: schema_version {version!r} has a different major version "
            f"than the supported {SCHEMA_VERSION!r}; a major change is breaking "
            "and must be agreed with the analysis owner.",
            file, field="schema_version")]
    if minor > supported_minor:
        return [_issue(
            "SCHEMA_MINOR_NEWER",
            f"{file}: schema_version {version!r} is newer than the supported "
            f"{SCHEMA_VERSION!r}. Minor changes are additive, so analysis can "
            "continue, but new fields will be ignored.",
            file, field="schema_version", severity=IssueSeverity.WARNING)]
    return []


# ----------------------------------------------------------------- records
def check_records(
    file: str, data: dict[str, Any], source: EvidenceSource
) -> list[ValidationIssue]:
    """Validate every record of one file against the contract."""
    records = data.get("records")
    if records is None:
        return []  # already reported as a missing/null envelope field
    if not isinstance(records, list):
        return [_issue(
            "RECORDS_NOT_LIST",
            f"{file}: 'records' must be a list, got {type(records).__name__}.",
            file, field="records")]

    issues: list[ValidationIssue] = []
    if not records:
        if source is EvidenceSource.SYSTEM:
            issues.append(_issue(
                "SYSTEM_RECORD_COUNT",
                f"{file}: must contain exactly one record, found 0.",
                file, field="records"))
        else:
            issues.append(_issue(
                "RECORDS_EMPTY",
                f"{file}: 'records' is empty. This is allowed, but confirm the "
                "collector really found nothing for this source.",
                file, field="records", severity=IssueSeverity.WARNING))
        return issues
    if source is EvidenceSource.SYSTEM and len(records) != 1:
        issues.append(_issue(
            "SYSTEM_RECORD_COUNT",
            f"{file}: must contain exactly one record, found {len(records)}.",
            file, field="records"))

    required = set(REQUIRED_RECORD_FIELDS[source])
    nullable_names = set(NULLABLE_REQUIRED_FIELDS.get(source, ()))
    positions: dict[str, list[int]] = {}
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            issues.append(_issue(
                "RECORD_NOT_OBJECT",
                f"{file} records[{index}]: record must be a JSON object, got "
                f"{type(record).__name__}.",
                file))
            continue
        raw_id = record.get("record_id")
        has_id = isinstance(raw_id, str) and bool(raw_id.strip())
        where = raw_id if has_id else f"records[{index}]"
        rid = raw_id if has_id else None

        for name, type_name in FIELD_TYPES[source].items():
            if name not in record:
                if name in required:
                    code = "RECORD_ID_MISSING" if name == "record_id" else "FIELD_MISSING"
                    issues.append(_issue(
                        code,
                        f"{file} {where}: required field '{name}' is missing.",
                        file, rid, name))
                continue
            issues += check_field(
                file, where, name, record[name], type_name, name in required,
                rid, nullable=name in nullable_names)
            allowed = FIELD_ALLOWED_VALUES.get(source, {}).get(name)
            if (allowed and isinstance(record[name], str)
                    and record[name] not in allowed):
                issues.append(_issue(
                    "FIELD_VALUE",
                    f"{file} {where}: field '{name}' is {record[name]!r}; "
                    f"allowed values are {', '.join(allowed)}.",
                    file, rid, name))

        if has_id:
            positions.setdefault(raw_id, []).append(index)
            issues += _check_record_id_format(file, raw_id, source)

    for record_id, where_list in positions.items():
        if len(where_list) > 1:
            spots = ", ".join(f"records[{i}]" for i in where_list)
            issues.append(_issue(
                "RECORD_ID_DUPLICATE",
                f"{file}: record_id {record_id!r} appears {len(where_list)} "
                f"times ({spots}). IDs must be unique.",
                file, record_id, "record_id"))
    return issues


def _check_record_id_format(
    file: str, record_id: str, source: EvidenceSource
) -> list[ValidationIssue]:
    prefix = RECORD_ID_PREFIX[source]
    if re.fullmatch(rf"{prefix}-\d{{4,}}", record_id):
        return []
    return [_issue(
        "RECORD_ID_FORMAT",
        f"{file} {record_id}: record_id must be '{prefix}-' followed by 4 or "
        f"more digits, e.g. '{prefix}-0001'.",
        file, record_id, "record_id")]
