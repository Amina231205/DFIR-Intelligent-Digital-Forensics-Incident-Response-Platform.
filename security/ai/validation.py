"""Structural and reference validation for the AI input/output contract."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from security.ai.contract import (
    AI_CONFIDENCE_LEVELS,
    AI_CONTRACT_VERSION,
    NEUTRAL_EMPTY_SUMMARY,
)


class AIContractValidationError(ValueError):
    """Raised when an AI contract payload is malformed or ungrounded."""


_COLLECTIONS = (
    "users_involved", "evidence_files", "timeline", "findings", "iocs",
    "mitre_mappings", "finding_assessments", "finding_links", "data_gaps",
    "evidence_integrity",
)


def _object(value: Any, path: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise AIContractValidationError(f"{path} must be an object")
    return value


def _array(value: Any, path: str) -> list[Any]:
    if not isinstance(value, list):
        raise AIContractValidationError(f"{path} must be an array")
    return value


def _strings(value: Any, path: str) -> list[str]:
    items = _array(value, path)
    if any(not isinstance(item, str) or not item for item in items):
        raise AIContractValidationError(f"{path} must contain non-empty strings")
    return items


def _optional_collection(result: Mapping[str, Any], name: str) -> list[Any]:
    value = result.get(name, [])
    if value is None:
        return []
    return _array(value, f"security_result.{name}")


def validate_ai_input(payload: Mapping[str, Any]) -> None:
    """Validate the wrapper and required identity fields of serialized input."""
    root = _object(payload, "AI input")
    if root.get("contract_version") != AI_CONTRACT_VERSION:
        raise AIContractValidationError("unsupported AI input contract_version")
    result = _object(root.get("security_result"), "security_result")
    if not isinstance(result.get("incident_id"), str) or not result["incident_id"].strip():
        raise AIContractValidationError("security_result.incident_id must be non-empty")
    if "schema_version" in result and not isinstance(result["schema_version"], str):
        raise AIContractValidationError("security_result.schema_version must be a string")
    for name in _COLLECTIONS:
        _optional_collection(result, name)
    # Check collection members are objects where the Security schema specifies
    # nested records. This is intentionally permissive about optional fields.
    for name in ("timeline", "findings", "iocs", "mitre_mappings", "finding_links", "finding_assessments"):
        for index, item in enumerate(_optional_collection(result, name)):
            _object(item, f"security_result.{name}[{index}]")


def _index(result: Mapping[str, Any]) -> dict[str, Any]:
    findings = {x["finding_id"]: x for x in _optional_collection(result, "findings")
                if isinstance(x, Mapping) and isinstance(x.get("finding_id"), str)}
    events = {x["event_id"]: x for x in _optional_collection(result, "timeline")
              if isinstance(x, Mapping) and isinstance(x.get("event_id"), str)}
    iocs = {x["ioc_id"]: x for x in _optional_collection(result, "iocs")
            if isinstance(x, Mapping) and isinstance(x.get("ioc_id"), str)}
    mappings = _optional_collection(result, "mitre_mappings")
    techniques: dict[str, list[Mapping[str, Any]]] = {}
    for mapping in mappings:
        if isinstance(mapping, Mapping) and isinstance(mapping.get("technique_id"), str):
            techniques.setdefault(mapping["technique_id"], []).append(mapping)

    links = {x["finding_id"]: x for x in _optional_collection(result, "finding_links")
             if isinstance(x, Mapping) and isinstance(x.get("finding_id"), str)}
    assessments = {x["finding_id"]: x for x in _optional_collection(result, "finding_assessments")
                   if isinstance(x, Mapping) and isinstance(x.get("finding_id"), str)}
    return {"findings": findings, "events": events, "iocs": iocs,
            "techniques": techniques, "links": links, "assessments": assessments}


def _list_field(obj: Mapping[str, Any], key: str) -> set[str]:
    value = obj.get(key, [])
    if not isinstance(value, list):
        return set()
    return {item for item in value if isinstance(item, str)}


def _finding_events(finding_id: str, idx: dict[str, Any]) -> set[str]:
    finding = idx["findings"].get(finding_id, {})
    linked = idx["links"].get(finding_id, {})
    assessment = idx["assessments"].get(finding_id, {})
    facts = assessment.get("observed_facts", {}) if isinstance(assessment, Mapping) else {}
    return (_list_field(finding, "supporting_events")
            | _list_field(linked, "event_ids")
            | _list_field(facts, "supporting_event_ids"))


def _finding_records(finding_id: str, idx: dict[str, Any]) -> set[str]:
    finding = idx["findings"].get(finding_id, {})
    linked = idx["links"].get(finding_id, {})
    assessment = idx["assessments"].get(finding_id, {})
    facts = assessment.get("observed_facts", {}) if isinstance(assessment, Mapping) else {}
    records = (_list_field(finding, "evidence_sources")
               | _list_field(linked, "evidence_record_ids")
               | _list_field(facts, "evidence_record_ids"))
    for indicator in finding.get("matched_indicators", []) if isinstance(finding, Mapping) else []:
        if isinstance(indicator, Mapping) and isinstance(indicator.get("evidence_id"), str):
            records.add(indicator["evidence_id"])
    return records


def _finding_iocs(finding_id: str, idx: dict[str, Any]) -> set[str]:
    return (_list_field(idx["findings"].get(finding_id, {}), "iocs")
            | _list_field(idx["links"].get(finding_id, {}), "ioc_ids"))


def _finding_techniques(finding_id: str, idx: dict[str, Any]) -> set[str]:
    techniques = _list_field(idx["findings"].get(finding_id, {}), "mitre_techniques")
    # Security's finding stores technique_id strings. Mapping relationships
    # independently confirm those strings through related_finding(s).
    for technique_id, mappings in idx["techniques"].items():
        if any(mapping.get("related_finding") == finding_id
               or finding_id in _list_field(mapping, "related_findings")
               for mapping in mappings):
            techniques.add(technique_id)
    return techniques


def _record_files(idx: dict[str, Any]) -> dict[str, set[str]]:
    """Files directly paired with record IDs in input structures only."""
    result: dict[str, set[str]] = {}
    for ioc in idx["iocs"].values():
        record_id, source = ioc.get("evidence_id"), ioc.get("source")
        if isinstance(record_id, str) and isinstance(source, str):
            result.setdefault(record_id, set()).add(source)
        for occurrence in ioc.get("occurrences", []):
            if not isinstance(occurrence, Mapping):
                continue
            record_id, source = occurrence.get("evidence_id"), occurrence.get("evidence_file")
            if isinstance(record_id, str) and isinstance(source, str):
                result.setdefault(record_id, set()).add(source)
    for finding in idx["findings"].values():
        for indicator in finding.get("matched_indicators", []):
            if not isinstance(indicator, Mapping):
                continue
            record_id, source = indicator.get("evidence_id"), indicator.get("evidence_file")
            if isinstance(record_id, str) and isinstance(source, str):
                result.setdefault(record_id, set()).add(source)
    return result


def _validate_supporting_evidence(value: Any, path: str, idx: dict[str, Any], files: dict[str, set[str]]) -> None:
    support = _object(value, path)
    categories = {
        "finding_ids": "findings", "event_ids": "events", "ioc_ids": "iocs",
    }
    ids: dict[str, list[str]] = {}
    for field, category in categories.items():
        ids[field] = _strings(support.get(field, []), f"{path}.{field}")
        unknown = set(ids[field]) - set(idx[category])
        if unknown:
            raise AIContractValidationError(f"{path}.{field} contains unknown IDs: {sorted(unknown)}")
    ids["attack_ids"] = _strings(support.get("attack_ids", []), f"{path}.attack_ids")
    unknown_attacks = set(ids["attack_ids"]) - set(idx["techniques"])
    if unknown_attacks:
        raise AIContractValidationError(f"{path}.attack_ids contains unknown IDs: {sorted(unknown_attacks)}")

    # Co-listed objects must be linked by Security's own relationships.
    for finding_id in ids["finding_ids"]:
        for event_id in ids["event_ids"]:
            if event_id not in _finding_events(finding_id, idx):
                raise AIContractValidationError(f"{path} links unrelated finding {finding_id} and event {event_id}")
        for ioc_id in ids["ioc_ids"]:
            finding = idx["findings"][finding_id]
            if ioc_id not in _finding_iocs(finding_id, idx) and finding_id not in _list_field(idx["iocs"][ioc_id], "related_findings"):
                raise AIContractValidationError(f"{path} links unrelated finding {finding_id} and IOC {ioc_id}")
        for attack_id in ids["attack_ids"]:
            mapping_linked = any(
                mapping.get("related_finding") == finding_id
                or finding_id in _list_field(mapping, "related_findings")
                for mapping in idx["techniques"][attack_id]
            )
            if attack_id not in _finding_techniques(finding_id, idx) or not mapping_linked:
                raise AIContractValidationError(f"{path} links unrelated finding {finding_id} and ATT&CK ID {attack_id}")

    evidence_refs = _array(support.get("evidence_refs", []), f"{path}.evidence_refs")
    for n, raw_ref in enumerate(evidence_refs):
        ref_path = f"{path}.evidence_refs[{n}]"
        ref = _object(raw_ref, ref_path)
        record_id = ref.get("evidence_id")
        if not isinstance(record_id, str) or not record_id:
            raise AIContractValidationError(f"{ref_path}.evidence_id must be non-empty")
        rel_fields = {
            "related_finding_ids": ("findings", ids["finding_ids"]),
            "related_event_ids": ("events", ids["event_ids"]),
            "related_ioc_ids": ("iocs", ids["ioc_ids"]),
        }
        relations: dict[str, list[str]] = {}
        for field, (category, allowed) in rel_fields.items():
            relations[field] = _strings(ref.get(field, []), f"{ref_path}.{field}")
            if set(relations[field]) - set(allowed):
                raise AIContractValidationError(f"{ref_path}.{field} must refer to entities in supporting_evidence")
            unknown = set(relations[field]) - set(idx[category])
            if unknown:
                raise AIContractValidationError(f"{ref_path}.{field} contains unknown IDs: {sorted(unknown)}")
        if not any(relations.values()):
            raise AIContractValidationError(f"{ref_path} must identify an associated finding, event, or IOC")

        for finding_id in relations["related_finding_ids"]:
            if record_id not in _finding_records(finding_id, idx):
                raise AIContractValidationError(f"{ref_path} record is not associated with finding {finding_id}")
        for event_id in relations["related_event_ids"]:
            if idx["events"][event_id].get("evidence_id") != record_id:
                raise AIContractValidationError(f"{ref_path} record is not associated with event {event_id}")
        for ioc_id in relations["related_ioc_ids"]:
            ioc = idx["iocs"][ioc_id]
            record_ids = {ioc.get("evidence_id")}
            record_ids.update(
                occurrence.get("evidence_id") for occurrence in ioc.get("occurrences", [])
                if isinstance(occurrence, Mapping)
            )
            if record_id not in record_ids:
                raise AIContractValidationError(f"{ref_path} record is not associated with IOC {ioc_id}")

        if "evidence_file" in ref:
            evidence_file = ref["evidence_file"]
            if not isinstance(evidence_file, str) or not evidence_file:
                raise AIContractValidationError(f"{ref_path}.evidence_file must be a non-empty string")
            if evidence_file not in files.get(record_id, set()):
                raise AIContractValidationError(f"{ref_path}.evidence_file is not directly associated with {record_id}")


def validate_ai_output(ai_input: Mapping[str, Any], output: Mapping[str, Any]) -> None:
    """Validate output shape, grounding references, and identity continuity."""
    validate_ai_input(ai_input)
    root = _object(ai_input, "AI input")
    security_result = _object(root["security_result"], "security_result")
    out = _object(output, "AI output")
    if out.get("contract_version") != AI_CONTRACT_VERSION:
        raise AIContractValidationError("unsupported AI output contract_version")
    if out.get("incident_id") != security_result["incident_id"]:
        raise AIContractValidationError("output incident_id must match security_result.incident_id")
    source_schema = security_result.get("schema_version", "")
    if out.get("source_schema_version") != source_schema:
        raise AIContractValidationError("output source_schema_version must match Security schema_version")

    idx = _index(security_result)
    files = _record_files(idx)
    observations = _array(out.get("observations"), "observations")
    hypotheses = _array(out.get("hypotheses"), "hypotheses")
    limitations = _strings(out.get("limitations"), "limitations")
    _strings(out.get("recommended_next_steps"), "recommended_next_steps")
    summary = out.get("executive_summary")
    if not isinstance(summary, str) or not summary.strip():
        raise AIContractValidationError("executive_summary must be non-empty")
    basis = _object(out.get("executive_summary_basis"), "executive_summary_basis")
    observation_basis = _strings(basis.get("observation_ids"), "executive_summary_basis.observation_ids")
    hypothesis_basis = _strings(basis.get("hypothesis_ids"), "executive_summary_basis.hypothesis_ids")

    observation_ids: set[str] = set()
    for n, raw in enumerate(observations):
        path = f"observations[{n}]"
        item = _object(raw, path)
        obs_id, statement = item.get("observation_id"), item.get("statement")
        if not isinstance(obs_id, str) or not obs_id or obs_id in observation_ids:
            raise AIContractValidationError(f"{path}.observation_id must be unique and non-empty")
        if not isinstance(statement, str) or not statement.strip():
            raise AIContractValidationError(f"{path}.statement must be non-empty")
        observation_ids.add(obs_id)
        _validate_supporting_evidence(item.get("supporting_evidence"), f"{path}.supporting_evidence", idx, files)

    hypothesis_ids: set[str] = set()
    for n, raw in enumerate(hypotheses):
        path = f"hypotheses[{n}]"
        item = _object(raw, path)
        hyp_id, statement = item.get("hypothesis_id"), item.get("statement")
        if not isinstance(hyp_id, str) or not hyp_id or hyp_id in hypothesis_ids:
            raise AIContractValidationError(f"{path}.hypothesis_id must be unique and non-empty")
        if not isinstance(statement, str) or not statement.strip():
            raise AIContractValidationError(f"{path}.statement must be non-empty")
        hypothesis_ids.add(hyp_id)
        _validate_supporting_evidence(item.get("supporting_evidence"), f"{path}.supporting_evidence", idx, files)
        confidence = _object(item.get("confidence"), f"{path}.confidence")
        if confidence.get("level") not in AI_CONFIDENCE_LEVELS:
            raise AIContractValidationError(f"{path}.confidence.level must be one of {AI_CONFIDENCE_LEVELS}")
        justification = confidence.get("justification")
        if not isinstance(justification, str) or not justification.strip():
            raise AIContractValidationError(f"{path}.confidence.justification must be non-empty")

    if set(observation_basis) - observation_ids or set(hypothesis_basis) - hypothesis_ids:
        raise AIContractValidationError("executive_summary_basis contains unknown statement IDs")
    if observations and not observation_basis:
        raise AIContractValidationError("executive_summary_basis must cite observations summarized")
    if hypotheses and not hypothesis_basis and not observation_basis:
        raise AIContractValidationError("executive_summary_basis must cite statements summarized")
    if not observations and not hypotheses:
        if summary != NEUTRAL_EMPTY_SUMMARY:
            raise AIContractValidationError("empty analysis must use the neutral executive summary")
        if observation_basis or hypothesis_basis:
            raise AIContractValidationError("empty analysis cannot cite summary basis IDs")
        if not limitations:
            raise AIContractValidationError("empty analysis requires explicit limitations")

