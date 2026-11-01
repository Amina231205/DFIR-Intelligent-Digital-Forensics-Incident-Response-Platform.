"""Strict input, relationship, and claim-token validation for AI responses."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Mapping
from typing import Any

from security.ai.contract import (
    AIAnalysis,
    AI_BASE_LIMITATIONS,
    AI_CONFIDENCE_LEVELS,
    AI_CONTRACT_VERSION,
    AIInput,
)
from security.ai.privacy import (
    ACTOR_REFERENCE_RE,
    CASE_REFERENCE_RE,
    DEVICE_REFERENCE_RE,
    build_ai_input,
)
from security.models.schemas import (
    SCHEMA_VERSION,
    Confidence,
    EventType,
    InvestigationResult,
    IOCType,
    RECORD_ID_PREFIX,
    Severity,
)


class AIContractValidationError(ValueError):
    """Raised when an AI payload is malformed, ungrounded, or non-authoritative."""


_COLLECTIONS = (
    "timeline", "findings", "iocs", "mitre_mappings", "fact_catalog",
)
_SUPPORT_FIELDS = (
    "finding_ids", "event_ids", "ioc_ids", "attack_ids", "evidence_refs",
)
_FACT_ID = re.compile(r"^FACT-\d{3,}$")
_FINDING_ID = re.compile(r"^F-\d{3,}$")
_EVENT_ID = re.compile(r"^E-\d{5,}$")
_IOC_ID = re.compile(r"^IOC-\d{3,}$")
_RULE_ID = re.compile(r"^DET-\d{3,}$")
_ATTACK_ID_FORMAT = re.compile(r"^T\d{4}(?:\.\d{3})?$")
_MAPPING_ID = re.compile(r"^MAP-T\d{4}(?:\.\d{3})?-TA\d{4}$")
_RECORD_ID = re.compile(r"^(?:SYS|PROC|NET|USR|EVL|PS|FILE)-\d{4,}$")
_MONTHS = (
    "January|February|March|April|May|June|July|August|September|October|"
    "November|December|Jan|Feb|Mar|Apr|Jun|Jul|Aug|Sep|Oct|Nov|Dec"
)
_TIMESTAMP = re.compile(
    rf"\b(?:\d{{4}}[-/]\d{{1,2}}[-/]\d{{1,2}}"
    rf"(?:[T ]\d{{2}}:\d{{2}}(?::\d{{2}}(?:\.\d+)?)?(?:Z|[+-]\d{{2}}:?\d{{2}})?)?"
    rf"|\d{{1,2}}[-/]\d{{1,2}}[-/]\d{{2,4}}"
    rf"|\d{{1,2}}:\d{{2}}(?::\d{{2}})?(?:\s?(?:UTC|GMT|AM|PM))?"
    rf"|(?:{_MONTHS})\s+\d{{1,2}}(?:st|nd|rd|th)?(?:,?\s+\d{{4}})?)\b",
    re.IGNORECASE,
)
_ID_PATTERNS = {
    "finding_ids": re.compile(r"\bF-\d{3,}\b"),
    "event_ids": re.compile(r"\bE-\d{5,}\b"),
    "ioc_ids": re.compile(r"\bIOC-\d{3,}\b"),
}
_EVIDENCE_ID = re.compile(r"\b(?:SYS|PROC|NET|USR|EVL|PS|FILE)-\d{4,}\b")
_ATTACK_ID = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
_URL = re.compile(r"\b(?:https?|ftp)://[^\s\"'<>]+", re.IGNORECASE)
_IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w])")
_DOMAIN = re.compile(
    r"(?<![@\w-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z]{2,63}(?![\w-])",
    re.IGNORECASE,
)
_HASH = re.compile(r"\b(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})\b", re.IGNORECASE)
_WINDOWS_PATH = re.compile(r"\b[A-Za-z]:\\[^\s\"'<>]+")
_UNC_PATH = re.compile(r"\\\\[^\\/\s]+\\[^\s\"'<>]+")
_POSIX_PATH = re.compile(r"(?<!\w)/(?:[^\s/]+/)*[^\s\"'<>]+")
_EVIDENCE_FILE_BY_PREFIX = {
    prefix: f"{source.value}.json"
    for source, prefix in RECORD_ID_PREFIX.items()
}
def _require_pattern(value: Any, pattern: re.Pattern[str], path: str) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise AIContractValidationError(f"{path} has an invalid format")
    return value


def _require_record_reference(record_id: Any, path: str) -> str:
    record_id = _require_pattern(record_id, _RECORD_ID, path)
    prefix = record_id.split("-", 1)[0]
    return _EVIDENCE_FILE_BY_PREFIX[prefix]


def _object(value: Any, path: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise AIContractValidationError(f"{path} must be an object")
    return value


def _array(value: Any, path: str) -> list[Any]:
    if not isinstance(value, list):
        raise AIContractValidationError(f"{path} must be an array")
    return value


def _strings(value: Any, path: str, *, unique: bool = False) -> list[str]:
    items = _array(value, path)
    if any(not isinstance(item, str) or not item for item in items):
        raise AIContractValidationError(f"{path} must contain non-empty strings")
    if unique and len(set(items)) != len(items):
        raise AIContractValidationError(f"{path} must not contain duplicates")
    return items


def _check_exact_keys(value: Mapping[str, Any], required: set[str], path: str) -> None:
    missing = required - set(value)
    extra = set(value) - required
    if missing:
        raise AIContractValidationError(f"{path} is missing fields: {sorted(missing)}")
    if extra:
        raise AIContractValidationError(f"{path} has unsupported fields: {sorted(extra)}")


def validate_ai_input(
    payload: Mapping[str, Any], *, source_result: InvestigationResult
) -> None:
    """Validate the privacy schema and bind context values to their source case."""
    if not isinstance(source_result, InvestigationResult):
        raise TypeError("source_result must be an InvestigationResult")
    root = _object(payload, "AI input")
    _check_exact_keys(root, {
        "contract_version", "incident_ref", "source_schema_version", "device_ref",
        *_COLLECTIONS,
    }, "AI input")
    if root["contract_version"] != AI_CONTRACT_VERSION:
        raise AIContractValidationError("unsupported AI input contract_version")
    incident_match = CASE_REFERENCE_RE.fullmatch(root["incident_ref"]) \
        if isinstance(root["incident_ref"], str) else None
    device_match = DEVICE_REFERENCE_RE.fullmatch(root["device_ref"]) \
        if isinstance(root["device_ref"], str) else None
    if incident_match is None:
        raise AIContractValidationError("incident_ref has an invalid privacy reference format")
    if device_match is None:
        raise AIContractValidationError("device_ref has an invalid privacy reference format")
    if device_match.group(1) != incident_match.group(1):
        raise AIContractValidationError("device_ref must use the incident privacy namespace")
    if root["source_schema_version"] != SCHEMA_VERSION:
        raise AIContractValidationError("source_schema_version is unsupported")
    objects = {
        name: [
            _object(item, f"{name}[{index}]")
            for index, item in enumerate(_array(root[name], name))
        ]
        for name in _COLLECTIONS
    }
    shapes = {
        "timeline": {"event_id", "sequence", "event_type", "actor_ref", "evidence_id", "evidence_file"},
        "findings": {"finding_id", "rule_id", "severity", "confidence", "supporting_events", "evidence_sources", "ioc_ids", "attack_ids"},
        "iocs": {"ioc_id", "type", "related_findings", "evidence_refs"},
        "mitre_mappings": {"mapping_id", "technique_id", "related_findings", "supporting_events", "evidence_sources", "ioc_ids"},
        "fact_catalog": {"fact_id", "statement", "verification_status", "supporting_evidence"},
    }
    for collection, expected in shapes.items():
        for index, item in enumerate(objects[collection]):
            _check_exact_keys(item, expected, f"{collection}[{index}]")
    for index, event in enumerate(objects["timeline"]):
        _require_pattern(event["event_id"], _EVENT_ID, f"timeline[{index}].event_id")
        if not isinstance(event["event_type"], str) or event["event_type"] not in {
            item.value for item in EventType
        }:
            raise AIContractValidationError(f"timeline[{index}].event_type is unsupported")
        expected_file = _require_record_reference(
            event["evidence_id"], f"timeline[{index}].evidence_id"
        )
        if event["evidence_file"] != expected_file:
            raise AIContractValidationError(
                f"timeline[{index}].evidence_file does not match evidence_id"
            )
        if type(event["sequence"]) is not int or event["sequence"] != index + 1:
            raise AIContractValidationError(
                f"timeline[{index}].sequence must match its ordered position"
            )
        if event["actor_ref"] is not None:
            _require_pattern(
                event["actor_ref"], ACTOR_REFERENCE_RE,
                f"timeline[{index}].actor_ref",
            )
    event_ids = [event["event_id"] for event in objects["timeline"]]
    if len(set(event_ids)) != len(event_ids):
        raise AIContractValidationError("timeline event IDs must be unique")
    actor_matches = [
        ACTOR_REFERENCE_RE.fullmatch(event["actor_ref"])
        for event in objects["timeline"] if event["actor_ref"] is not None
    ]
    if any(match.group(1) != incident_match.group(1) for match in actor_matches):
        raise AIContractValidationError("actor_ref must use the incident privacy namespace")
    actor_ordinals = {int(match.group(2)) for match in actor_matches}
    if actor_ordinals != set(range(1, len(actor_ordinals) + 1)):
        raise AIContractValidationError("actor_ref ordinals must be contiguous within the case")
    for index, finding in enumerate(objects["findings"]):
        _require_pattern(finding["finding_id"], _FINDING_ID, f"findings[{index}].finding_id")
        _require_pattern(finding["rule_id"], _RULE_ID, f"findings[{index}].rule_id")
        if not isinstance(finding["severity"], str) or finding["severity"] not in {
            item.value for item in Severity
        }:
            raise AIContractValidationError(f"findings[{index}].severity is unsupported")
        if not isinstance(finding["confidence"], str) or finding["confidence"] not in {
            item.value for item in Confidence
        }:
            raise AIContractValidationError(f"findings[{index}].confidence is unsupported")
    collection_patterns = (
        ("findings", "finding_id", _FINDING_ID, {
            "supporting_events": _EVENT_ID,
            "evidence_sources": _RECORD_ID,
            "ioc_ids": _IOC_ID,
            "attack_ids": _ATTACK_ID_FORMAT,
        }),
        ("iocs", "ioc_id", _IOC_ID, {"related_findings": _FINDING_ID}),
        ("mitre_mappings", "mapping_id", _MAPPING_ID, {
            "related_findings": _FINDING_ID,
            "supporting_events": _EVENT_ID,
            "evidence_sources": _RECORD_ID,
            "ioc_ids": _IOC_ID,
        }),
    )
    for collection, id_field, id_pattern, field_patterns in collection_patterns:
        identifiers = []
        for index, item in enumerate(objects[collection]):
            identifier = _require_pattern(
                item[id_field], id_pattern, f"{collection}[{index}].{id_field}"
            )
            identifiers.append(identifier)
            for field, pattern in field_patterns.items():
                values = _strings(item[field], f"{collection}[{index}].{field}", unique=True)
                for value_index, value in enumerate(values):
                    _require_pattern(
                        value, pattern,
                        f"{collection}[{index}].{field}[{value_index}]",
                    )
        if len(set(identifiers)) != len(identifiers):
            raise AIContractValidationError(f"{collection} IDs must be unique")
    for index, ioc in enumerate(objects["iocs"]):
        if not isinstance(ioc["type"], str) or ioc["type"] not in {
            item.value for item in IOCType
        }:
            raise AIContractValidationError(f"iocs[{index}].type is unsupported")
        for ref_index, raw_ref in enumerate(_array(ioc["evidence_refs"], f"iocs[{index}].evidence_refs")):
            ref = _object(raw_ref, f"iocs[{index}].evidence_refs[{ref_index}]")
            ref_fields = {"evidence_id"}
            if "evidence_file" in ref:
                ref_fields.add("evidence_file")
            _check_exact_keys(ref, ref_fields, f"iocs[{index}].evidence_refs[{ref_index}]")
            expected_file = _require_record_reference(
                ref.get("evidence_id"),
                f"iocs[{index}].evidence_refs[{ref_index}].evidence_id",
            )
            if "evidence_file" in ref and ref["evidence_file"] != expected_file:
                raise AIContractValidationError(
                    f"iocs[{index}].evidence_refs[{ref_index}].evidence_file "
                    "does not match evidence_id"
                )
    for index, mapping in enumerate(objects["mitre_mappings"]):
        _require_pattern(
            mapping["technique_id"], _ATTACK_ID_FORMAT,
            f"mitre_mappings[{index}].technique_id",
        )
    fact_ids = []
    for index, fact in enumerate(objects["fact_catalog"]):
        fact_id = fact["fact_id"]
        if not isinstance(fact_id, str) or not _FACT_ID.fullmatch(fact_id):
            raise AIContractValidationError(f"fact_catalog[{index}].fact_id is invalid")
        if not isinstance(fact["statement"], str) or not fact["statement"].strip():
            raise AIContractValidationError(f"fact_catalog[{index}].statement must be non-empty")
        if fact["verification_status"] != "source_recorded":
            raise AIContractValidationError(
                f"fact_catalog[{index}].verification_status must be 'source_recorded'"
            )
        fact_ids.append(fact_id)
    if len(set(fact_ids)) != len(fact_ids):
        raise AIContractValidationError("fact_catalog IDs must be unique")

    index = _index(root)
    attack_ids = set(index["techniques"])
    for number, fact in enumerate(objects["fact_catalog"]):
        fact_support = _validate_support(
            fact["supporting_evidence"], f"fact_catalog[{number}].supporting_evidence",
            index, allowed_attack_ids=attack_ids,
        )
        finding_ids = fact_support["finding_ids"]
        if len(finding_ids) != 1:
            raise AIContractValidationError(
                f"fact_catalog[{number}] must identify exactly one deterministic finding"
            )
        finding = index["findings"][finding_ids[0]]
        expected_statement = (
            f"The deterministic analysis produced finding {finding['finding_id']} "
            f"under rule {finding['rule_id']}."
        )
        if fact["statement"] != expected_statement:
            raise AIContractValidationError(
                f"fact_catalog[{number}].statement does not match its deterministic finding"
            )
        try:
            finding_number = next(
                index for index, item in enumerate(objects["findings"], start=1)
                if item["finding_id"] == finding["finding_id"]
            )
        except StopIteration as exc:
            raise AIContractValidationError(
                f"fact_catalog[{number}] references an unknown finding"
            ) from exc
        if fact["fact_id"] != f"FACT-{finding_number:03d}":
            raise AIContractValidationError(
                f"fact_catalog[{number}].fact_id does not match its finding"
            )
    _validate_context_relationships(objects, index)
    if dict(root) != build_ai_input(source_result):
        raise AIContractValidationError(
            "AI input does not match the minimized context from the source investigation"
        )


def _index(payload: Mapping[str, Any]) -> dict[str, Any]:
    findings = {item["finding_id"]: item for item in payload["findings"]}
    events = {item["event_id"]: item for item in payload["timeline"]}
    iocs = {item["ioc_id"]: item for item in payload["iocs"]}
    record_files = {
        event["evidence_id"]: event["evidence_file"]
        for event in payload["timeline"]
    }
    for ioc in payload["iocs"]:
        for ref in ioc["evidence_refs"]:
            if isinstance(ref.get("evidence_id"), str) and isinstance(ref.get("evidence_file"), str):
                record_files[ref["evidence_id"]] = ref["evidence_file"]
    techniques: dict[str, list[Mapping[str, Any]]] = {}
    for mapping in payload["mitre_mappings"]:
        techniques.setdefault(mapping["technique_id"], []).append(mapping)
    return {"findings": findings, "events": events, "iocs": iocs,
            "record_files": record_files,
            "techniques": techniques}


def _string_set(obj: Mapping[str, Any], key: str) -> set[str]:
    value = obj.get(key, [])
    return {item for item in value if isinstance(item, str)} if isinstance(value, list) else set()


def _validate_context_relationships(
    objects: Mapping[str, list[Mapping[str, Any]]], index: Mapping[str, Any]
) -> None:
    """Ensure the allowlisted context preserves only known source links."""
    finding_ids = set(index["findings"])
    event_ids = set(index["events"])
    ioc_ids = set(index["iocs"])
    attack_ids = set(index["techniques"])
    record_ids = set(index["record_files"])
    record_ids.update(
        record_id
        for collection in (objects["findings"], objects["mitre_mappings"])
        for item in collection
        for record_id in item["evidence_sources"]
    )

    for finding in objects["findings"]:
        fid = finding["finding_id"]
        for field, known in (
            ("supporting_events", event_ids), ("evidence_sources", record_ids),
            ("ioc_ids", ioc_ids), ("attack_ids", attack_ids),
        ):
            unknown = set(finding[field]) - known
            if unknown:
                raise AIContractValidationError(
                    f"findings.{field} contains unknown IDs: {sorted(unknown)}"
                )
        for ioc_id in finding["ioc_ids"]:
            if fid not in _string_set(index["iocs"][ioc_id], "related_findings"):
                raise AIContractValidationError(
                    f"finding {fid} and IOC {ioc_id} have inconsistent relationships"
                )
        for attack_id in finding["attack_ids"]:
            if not any(fid in _string_set(mapping, "related_findings")
                       for mapping in index["techniques"][attack_id]):
                raise AIContractValidationError(
                    f"finding {fid} and ATT&CK ID {attack_id} have inconsistent relationships"
                )

    for ioc in objects["iocs"]:
        iid = ioc["ioc_id"]
        unknown = set(ioc["related_findings"]) - finding_ids
        if unknown:
            raise AIContractValidationError(
                f"iocs.related_findings contains unknown IDs: {sorted(unknown)}"
            )
        for ref in ioc["evidence_refs"]:
            if ref["evidence_id"] not in record_ids:
                raise AIContractValidationError(
                    f"IOC {iid} references unknown evidence ID {ref['evidence_id']}"
                )

    for mapping in objects["mitre_mappings"]:
        mid = mapping["mapping_id"]
        for field, known in (
            ("related_findings", finding_ids), ("supporting_events", event_ids),
            ("evidence_sources", record_ids), ("ioc_ids", ioc_ids),
        ):
            unknown = set(mapping[field]) - known
            if unknown:
                raise AIContractValidationError(
                    f"mitre_mappings.{field} contains unknown IDs: {sorted(unknown)}"
                )
        technique = mapping["technique_id"]
        if not isinstance(technique, str) or not technique:
            raise AIContractValidationError(f"mapping {mid} has invalid technique_id")
        for fid in mapping["related_findings"]:
            if technique not in _string_set(index["findings"][fid], "attack_ids"):
                raise AIContractValidationError(
                    f"mapping {mid} and finding {fid} have inconsistent relationships"
                )
        for event_id in mapping["supporting_events"]:
            if not any(event_id in _string_set(index["findings"][fid], "supporting_events")
                       for fid in mapping["related_findings"]):
                raise AIContractValidationError(
                    f"mapping {mid} has an event unrelated to its findings"
                )
        for ioc_id in mapping["ioc_ids"]:
            if not any(ioc_id in _string_set(index["findings"][fid], "ioc_ids")
                       for fid in mapping["related_findings"]):
                raise AIContractValidationError(
                    f"mapping {mid} has an IOC unrelated to its findings"
                )


def _validate_support(
    value: Any,
    path: str,
    idx: dict[str, Any],
    *,
    allowed_attack_ids: set[str],
) -> dict[str, list[Any]]:
    support = _object(value, path)
    _check_exact_keys(support, set(_SUPPORT_FIELDS), path)
    ids = {
        field: _strings(support[field], f"{path}.{field}", unique=True)
        for field in _SUPPORT_FIELDS if field != "evidence_refs"
    }
    categories = {
        "finding_ids": "findings", "event_ids": "events", "ioc_ids": "iocs",
    }
    for field, category in categories.items():
        unknown = set(ids[field]) - set(idx[category])
        if unknown:
            raise AIContractValidationError(f"{path}.{field} contains unknown IDs: {sorted(unknown)}")
    if set(ids["attack_ids"]) - allowed_attack_ids:
        raise AIContractValidationError(
            f"{path}.attack_ids contains unknown IDs: "
            f"{sorted(set(ids['attack_ids']) - allowed_attack_ids)}"
        )
    if not any(ids[field] for field in ("finding_ids", "event_ids")):
        raise AIContractValidationError(f"{path} must cite at least one finding or event ID")

    for finding_id in ids["finding_ids"]:
        finding = idx["findings"][finding_id]
        for event_id in ids["event_ids"]:
            if event_id not in _string_set(finding, "supporting_events"):
                raise AIContractValidationError(
                    f"{path} links unrelated finding {finding_id} and event {event_id}"
                )
        for ioc_id in ids["ioc_ids"]:
            ioc = idx["iocs"][ioc_id]
            if (ioc_id not in _string_set(finding, "ioc_ids")
                    and finding_id not in _string_set(ioc, "related_findings")):
                raise AIContractValidationError(
                    f"{path} links unrelated finding {finding_id} and IOC {ioc_id}"
                )
        for attack_id in ids["attack_ids"]:
            if (attack_id not in _string_set(finding, "attack_ids")
                    and not any(finding_id in _string_set(mapping, "related_findings")
                                for mapping in idx["techniques"][attack_id])):
                raise AIContractValidationError(
                    f"{path} links unrelated finding {finding_id} and ATT&CK ID {attack_id}"
                )

    # Validate co-cited entities even when the response omits a finding ID.
    # IDs must be related by the source context, not merely all exist.
    if not ids["finding_ids"]:
        for event_id in ids["event_ids"]:
            event = idx["events"][event_id]
            record_id = event["evidence_id"]
            for ioc_id in ids["ioc_ids"]:
                ioc_records = {
                    ref.get("evidence_id")
                    for ref in idx["iocs"][ioc_id]["evidence_refs"]
                }
                if record_id not in ioc_records:
                    raise AIContractValidationError(
                        f"{path} links unrelated event {event_id} and IOC {ioc_id}"
                    )
            for attack_id in ids["attack_ids"]:
                if not any(event_id in _string_set(mapping, "supporting_events")
                           for mapping in idx["techniques"][attack_id]):
                    raise AIContractValidationError(
                        f"{path} links unrelated event {event_id} and ATT&CK ID {attack_id}"
                    )
        for ioc_id in ids["ioc_ids"]:
            for attack_id in ids["attack_ids"]:
                if not any(ioc_id in _string_set(mapping, "ioc_ids")
                           for mapping in idx["techniques"][attack_id]):
                    raise AIContractValidationError(
                        f"{path} links unrelated IOC {ioc_id} and ATT&CK ID {attack_id}"
                    )

    refs = _array(support["evidence_refs"], f"{path}.evidence_refs")
    if not refs and not ids["finding_ids"] and not ids["event_ids"]:
        raise AIContractValidationError(f"{path} has no supporting references")
    for number, raw_ref in enumerate(refs):
        ref_path = f"{path}.evidence_refs[{number}]"
        ref = _object(raw_ref, ref_path)
        required = {"evidence_id", "related_finding_ids", "related_event_ids", "related_ioc_ids"}
        if "evidence_file" in ref:
            required.add("evidence_file")
        _check_exact_keys(ref, required, ref_path)
        record_id = ref["evidence_id"]
        if not isinstance(record_id, str) or not record_id:
            raise AIContractValidationError(f"{ref_path}.evidence_id must be non-empty")
        relations = {
            field: _strings(ref[field], f"{ref_path}.{field}", unique=True)
            for field in ("related_finding_ids", "related_event_ids", "related_ioc_ids")
        }
        permitted = {
            "related_finding_ids": set(ids["finding_ids"]),
            "related_event_ids": set(ids["event_ids"]),
            "related_ioc_ids": set(ids["ioc_ids"]),
        }
        for field, linked_ids in relations.items():
            if not set(linked_ids) <= permitted[field]:
                raise AIContractValidationError(
                    f"{ref_path}.{field} must refer to items in supporting_evidence"
                )
        if not any(relations.values()):
            raise AIContractValidationError(f"{ref_path} must identify an associated entity")

        for event_id in relations["related_event_ids"]:
            if idx["events"][event_id]["evidence_id"] != record_id:
                raise AIContractValidationError(
                    f"{ref_path} record is not associated with event {event_id}"
                )
        if "evidence_file" in ref and idx["record_files"].get(record_id) != ref["evidence_file"]:
            raise AIContractValidationError(
                f"{ref_path}.evidence_file is not associated with {record_id}"
            )
        for finding_id in relations["related_finding_ids"]:
            finding = idx["findings"][finding_id]
            if record_id not in _string_set(finding, "evidence_sources") and not any(
                event["evidence_id"] == record_id
                and event["event_id"] in _string_set(finding, "supporting_events")
                for event in idx["events"].values()
            ):
                raise AIContractValidationError(
                    f"{ref_path} record is not associated with finding {finding_id}"
                )
        for ioc_id in relations["related_ioc_ids"]:
            if not any(ref_item.get("evidence_id") == record_id
                       for ref_item in idx["iocs"][ioc_id].get("evidence_refs", [])):
                raise AIContractValidationError(
                    f"{ref_path} record is not associated with IOC {ioc_id}"
                )
    return ids


def _source_value_index(result: InvestigationResult) -> dict[str, Any]:
    ioc_values: dict[str, set[str]] = {}
    for ioc in result.iocs:
        candidates = {ioc.value}
        candidates.update(
            value for value in ioc.attributes.get("paths", []) if isinstance(value, str)
        )
        for value in candidates:
            ioc_values.setdefault(value.casefold(), set()).add(ioc.ioc_id)
    timestamps = {
        event.timestamp.isoformat().replace("+00:00", "Z"): event.event_id
        for event in result.timeline
    }
    return {"ioc_values": ioc_values, "timestamps": timestamps,
            "techniques": {mapping.technique_id for mapping in result.mitre_mappings}}


def _validate_claim_literals(
    text: str,
    support: dict[str, list[Any]],
    source_values: dict[str, Any],
    path: str,
) -> None:
    cited = {field: set(support[field]) for field in _SUPPORT_FIELDS if field != "evidence_refs"}
    for field, pattern in _ID_PATTERNS.items():
        for token in pattern.findall(text):
            if token not in cited[field]:
                raise AIContractValidationError(f"{path} contains uncited identifier {token}")
    for token in _EVIDENCE_ID.findall(text):
        if not any(ref.get("evidence_id") == token for ref in support["evidence_refs"]):
            raise AIContractValidationError(f"{path} contains uncited evidence identifier {token}")
    for token in _ATTACK_ID.findall(text):
        if token not in source_values["techniques"] or token not in cited["attack_ids"]:
            raise AIContractValidationError(f"{path} contains unsupported ATT&CK identifier {token}")

    for token in _TIMESTAMP.findall(text):
        event_id = source_values["timestamps"].get(token)
        if event_id is None or event_id not in cited["event_ids"]:
            raise AIContractValidationError(f"{path} contains unsupported timestamp {token}")

    ioc_tokens: set[str] = set()
    url_tokens = _URL.findall(text)
    ioc_tokens.update(url_tokens)
    for token in _IPV4.findall(text):
        try:
            ipaddress.ip_address(token)
        except ValueError:
            continue
        ioc_tokens.add(token)
    ioc_tokens.update(_HASH.findall(text))
    ioc_tokens.update(_WINDOWS_PATH.findall(text))
    ioc_tokens.update(_UNC_PATH.findall(text))
    ioc_tokens.update(_POSIX_PATH.findall(text))
    ioc_tokens.update(
        token for token in _DOMAIN.findall(text)
        if not any(token.casefold() in url.casefold() for url in url_tokens)
    )
    for token in ioc_tokens:
        normalized = token.rstrip(".,;:!?)]}").casefold()
        related_ioc_ids = source_values["ioc_values"].get(normalized, set())
        if not related_ioc_ids or not related_ioc_ids.intersection(cited["ioc_ids"]):
            raise AIContractValidationError(f"{path} contains unsupported indicator value {token}")


def _validate_claim(
    raw: Any,
    path: str,
    *,
    id_field: str,
    text_field: str,
    status_field: str,
    required_status: str,
    has_confidence: bool,
    fixed_fields: Mapping[str, str] | None,
    idx: dict[str, Any],
    allowed_attack_ids: set[str],
    source_values: dict[str, Any],
) -> dict[str, Any]:
    item = _object(raw, path)
    expected = {id_field, text_field, status_field, "supporting_evidence"}
    if has_confidence:
        expected.add("confidence")
    if fixed_fields:
        expected.update(fixed_fields)
    _check_exact_keys(item, expected, path)
    claim_id = item[id_field]
    text = item[text_field]
    if not isinstance(claim_id, str) or not claim_id.strip():
        raise AIContractValidationError(f"{path}.{id_field} must be non-empty")
    if not isinstance(text, str) or not text.strip():
        raise AIContractValidationError(f"{path}.{text_field} must be non-empty")
    if item[status_field] != required_status:
        raise AIContractValidationError(f"{path}.{status_field} must be {required_status!r}")
    for field, required_value in (fixed_fields or {}).items():
        if item[field] != required_value:
            raise AIContractValidationError(f"{path}.{field} must be {required_value!r}")
    support = _validate_support(
        item["supporting_evidence"], f"{path}.supporting_evidence", idx,
        allowed_attack_ids=allowed_attack_ids,
    )
    _validate_claim_literals(text, support, source_values, f"{path}.{text_field}")
    clean = dict(item)
    if has_confidence:
        confidence = _object(item["confidence"], f"{path}.confidence")
        _check_exact_keys(confidence, {"level", "justification"}, f"{path}.confidence")
        if confidence["level"] not in AI_CONFIDENCE_LEVELS:
            raise AIContractValidationError(
                f"{path}.confidence.level must be one of {AI_CONFIDENCE_LEVELS}"
            )
        justification = confidence["justification"]
        if not isinstance(justification, str) or not justification.strip():
            raise AIContractValidationError(f"{path}.confidence.justification must be non-empty")
        _validate_claim_literals(
            justification, support, source_values,
            f"{path}.confidence.justification",
        )
    return clean


def validate_ai_output(
    ai_input: Mapping[str, Any],
    output: Mapping[str, Any],
    *,
    source_result: InvestigationResult,
) -> AIAnalysis:
    """Validate v2 output and resolve facts from the local fact catalogue."""
    if not isinstance(source_result, InvestigationResult):
        raise TypeError("source_result must be an InvestigationResult")
    validate_ai_input(ai_input, source_result=source_result)
    root = _object(output, "AI provider output")
    expected_fields = {
        "contract_version", "incident_ref", "source_schema_version",
        "confirmed_fact_ids", "observations", "hypotheses", "recommendations",
    }
    _check_exact_keys(root, expected_fields, "AI provider output")
    for key in ("contract_version", "incident_ref", "source_schema_version"):
        if root[key] != ai_input[key]:
            raise AIContractValidationError(f"{key} must match the AI input")
    idx = _index(ai_input)
    allowed_attack_ids = set(idx["techniques"])
    source_values = _source_value_index(source_result)
    fact_catalog = {fact["fact_id"]: fact for fact in ai_input["fact_catalog"]}
    fact_ids = _strings(root["confirmed_fact_ids"], "confirmed_fact_ids", unique=True)
    unknown_facts = set(fact_ids) - set(fact_catalog)
    if unknown_facts or any(not _FACT_ID.fullmatch(fact_id) for fact_id in fact_ids):
        raise AIContractValidationError(f"confirmed_fact_ids contains unknown IDs: {sorted(unknown_facts)}")
    confirmed_facts = [fact_catalog[fact_id] for fact_id in fact_ids]

    observations = _array(root["observations"], "observations")
    hypotheses = _array(root["hypotheses"], "hypotheses")
    recommendations = _array(root["recommendations"], "recommendations")
    validated_observations = [
        _validate_claim(
            item, f"observations[{index}]", id_field="observation_id",
            text_field="statement", status_field="verification_status",
            required_status="unverified", has_confidence=True, fixed_fields=None, idx=idx,
            allowed_attack_ids=allowed_attack_ids, source_values=source_values,
        )
        for index, item in enumerate(observations)
    ]
    validated_hypotheses = [
        _validate_claim(
            item, f"hypotheses[{index}]", id_field="hypothesis_id",
            text_field="statement", status_field="verification_status",
            required_status="unverified", has_confidence=True, fixed_fields=None, idx=idx,
            allowed_attack_ids=allowed_attack_ids, source_values=source_values,
        )
        for index, item in enumerate(hypotheses)
    ]
    validated_recommendations = [
        _validate_claim(
            item, f"recommendations[{index}]", id_field="recommendation_id",
            text_field="action", status_field="status", required_status="analyst_review",
            has_confidence=False, fixed_fields={"classification": "suggestion"},
            idx=idx, allowed_attack_ids=allowed_attack_ids,
            source_values=source_values,
        )
        for index, item in enumerate(recommendations)
    ]
    for collection, id_field, label in (
        (validated_observations, "observation_id", "observation"),
        (validated_hypotheses, "hypothesis_id", "hypothesis"),
        (validated_recommendations, "recommendation_id", "recommendation"),
    ):
        identifiers = [item[id_field] for item in collection]
        if len(set(identifiers)) != len(identifiers):
            raise AIContractValidationError(f"{label} IDs must be unique")

    limitations = list(AI_BASE_LIMITATIONS)
    return {
        "contract_version": AI_CONTRACT_VERSION,
        "incident_ref": ai_input["incident_ref"],
        "source_schema_version": ai_input["source_schema_version"],
        "confirmed_facts": confirmed_facts,
        "observations": validated_observations,
        "hypotheses": validated_hypotheses,
        "recommendations": validated_recommendations,
        "limitations": limitations,
    }  # type: ignore[return-value]
