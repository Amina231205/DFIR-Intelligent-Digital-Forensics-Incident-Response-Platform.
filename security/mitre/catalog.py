"""Load and validate the ATT&CK dataset and the mapping definitions.

Two data files drive the mapping stage; neither contains logic:

* ``attack_subset.json``: the curated, identifiable ATT&CK data (version,
  source URL, SHA-256, retrieval time, techniques, tactics). Built by
  ``scripts/build_attack_subset.py`` from the official STIX bundle.
* ``mappings.json``: which findings map to which technique and tactic, under
  which evidence conditions, with what confidence and rationale.

Loading cross-checks them, so a definition cannot reference an invented
technique, a tactic the technique does not belong to, a revoked technique, or
an ATT&CK version that was not reviewed. Any problem raises ``ValueError``
naming the file.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional, Union

from security.mitre import conditions

PACKAGE_DIR = Path(__file__).resolve().parent
DEFAULT_ATTACK_PATH = PACKAGE_DIR / "attack_subset.json"
DEFAULT_MAPPINGS_PATH = PACKAGE_DIR / "mappings.json"
CONFIDENCE_LEVELS = ("Low", "Medium", "High")

_TECHNIQUE_ID = re.compile(r"^T\d{4}(\.\d{3})?$")
_TACTIC_ID = re.compile(r"^TA\d{4}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


@dataclass(frozen=True)
class Tactic:
    id: str
    name: str
    shortname: str
    url: str


@dataclass(frozen=True)
class Technique:
    id: str
    name: str
    is_subtechnique: bool
    parent_id: Optional[str]
    tactic_ids: tuple[str, ...]
    url: str
    version: Optional[str]
    modified: str
    used_by_mappings: bool


@dataclass(frozen=True)
class AttackDataset:
    metadata: dict[str, Any]
    tactics: dict[str, Tactic]
    techniques: dict[str, Technique]

    def display_name(self, technique_id: str) -> str:
        """ATT&CK display form: ``Parent: Sub`` for sub-techniques, else the name."""
        technique = self.techniques[technique_id]
        if technique.parent_id:
            return f"{self.techniques[technique.parent_id].name}: {technique.name}"
        return technique.name


@dataclass(frozen=True)
class ConfidenceSpec:
    base: str
    raised: Optional[str]
    raise_when: Optional[dict[str, Any]]
    raise_reason: str


@dataclass(frozen=True)
class MappingRule:
    id: str
    rule_id: str                       # the detection rule whose findings are mapped
    technique_id: str
    tactic_id: str
    tactic_reason: str
    conditions: dict[str, Any]
    evidence: list[dict[str, Any]]
    iocs: dict[str, Any]
    confidence: ConfidenceSpec
    rationale: str
    limitations: str


@dataclass(frozen=True)
class NotMapped:
    technique_id: str
    reason: str


@dataclass(frozen=True)
class MappingCatalog:
    dataset: AttackDataset
    rules: tuple[MappingRule, ...]
    not_mapped: tuple[NotMapped, ...]
    definition: dict[str, Any]
    confidence_scale: dict[str, str]

    def rules_for(self, detection_rule_id: str) -> tuple[MappingRule, ...]:
        return tuple(r for r in self.rules if r.rule_id == detection_rule_id)

    def supported_technique_ids(self) -> list[str]:
        return sorted({r.technique_id for r in self.rules})


# ------------------------------------------------------------------ helpers
def _read(path: Path, label: str) -> dict[str, Any]:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ValueError(f"{label}: cannot read {path}: {exc}") from None
    if not isinstance(data, dict):
        raise ValueError(f"{label}: top level must be a JSON object")
    return data


def _text(label: str, obj: Any, key: str) -> str:
    value = obj.get(key) if isinstance(obj, dict) else None
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label}: '{key}' must be a non-empty string")
    return value


def _exact(label: str, obj: dict, required: set[str], optional: set[str] = frozenset()) -> None:
    missing = sorted(required - set(obj))
    unknown = sorted(set(obj) - required - set(optional))
    if missing:
        raise ValueError(f"{label}: missing key(s) {missing}")
    if unknown:
        raise ValueError(f"{label}: unknown key(s) {unknown}")


# ------------------------------------------------------------------ dataset
def load_dataset(path: Union[str, Path] = DEFAULT_ATTACK_PATH) -> AttackDataset:
    """Load and validate an ATT&CK subset file."""
    label = Path(path).name
    data = _read(Path(path), label)
    _exact(label, data, {"metadata", "tactics", "techniques"})

    metadata = data["metadata"]
    if not isinstance(metadata, dict):
        raise ValueError(f"{label}: 'metadata' must be an object")
    for key in ("dataset", "attack_version", "attack_spec_version", "source_url",
                "retrieved_utc", "kind", "coverage_note", "source_sha256"):
        _text(f"{label}: metadata", metadata, key)
    if not _SHA256.match(metadata["source_sha256"]):
        raise ValueError(f"{label}: metadata.source_sha256 must be 64 lowercase hex digits")
    if not _UTC.match(metadata["retrieved_utc"]):
        raise ValueError(f"{label}: metadata.retrieved_utc must look like 2026-10-12T22:09:13Z")

    tactics: dict[str, Tactic] = {}
    if not isinstance(data["tactics"], list) or not data["tactics"]:
        raise ValueError(f"{label}: 'tactics' must be a non-empty list")
    for item in data["tactics"]:
        at = f"{label}: tactic {item.get('id') if isinstance(item, dict) else item!r}"
        tactic = Tactic(_text(at, item, "id"), _text(at, item, "name"),
                        _text(at, item, "shortname"), str(item.get("url", "")))
        if not _TACTIC_ID.match(tactic.id):
            raise ValueError(f"{at}: id must look like TA0001")
        if tactic.id in tactics:
            raise ValueError(f"{at}: duplicate tactic id")
        tactics[tactic.id] = tactic

    techniques: dict[str, Technique] = {}
    if not isinstance(data["techniques"], list) or not data["techniques"]:
        raise ValueError(f"{label}: 'techniques' must be a non-empty list")
    for item in data["techniques"]:
        at = f"{label}: technique {item.get('id') if isinstance(item, dict) else item!r}"
        tid = _text(at, item, "id")
        if not _TECHNIQUE_ID.match(tid):
            raise ValueError(f"{at}: id must look like T1059 or T1059.001")
        if tid in techniques:
            raise ValueError(f"{at}: duplicate technique id")
        sub, parent = item.get("is_subtechnique"), item.get("parent_id")
        if not isinstance(sub, bool) or sub != ("." in tid):
            raise ValueError(f"{at}: 'is_subtechnique' must be a boolean matching the id")
        if sub and parent != tid.split(".")[0]:
            raise ValueError(f"{at}: parent_id must be {tid.split('.')[0]}")
        if not sub and parent is not None:
            raise ValueError(f"{at}: a technique has no parent_id")
        tactic_ids = item.get("tactics")
        if (not isinstance(tactic_ids, list) or not tactic_ids
                or any(t not in tactics for t in tactic_ids)):
            raise ValueError(f"{at}: 'tactics' must list known tactic ids")
        if not isinstance(item.get("used_by_mappings"), bool):
            raise ValueError(f"{at}: 'used_by_mappings' must be true or false")
        techniques[tid] = Technique(
            tid, _text(at, item, "name"), sub, parent, tuple(sorted(tactic_ids)),
            str(item.get("url", "")), item.get("version"), str(item.get("modified", "")),
            item["used_by_mappings"])
    for technique in techniques.values():
        if technique.parent_id and technique.parent_id not in techniques:
            raise ValueError(f"{label}: parent {technique.parent_id} of {technique.id} "
                             "is not in the dataset")
    if metadata.get("technique_count") != len(techniques):
        raise ValueError(f"{label}: metadata.technique_count does not match the techniques")
    return AttackDataset(dict(metadata), tactics, techniques)


# ----------------------------------------------------------------- mappings
def _confidence(label: str, spec: Any) -> ConfidenceSpec:
    if not isinstance(spec, dict):
        raise ValueError(f"{label}: 'confidence' must be an object")
    _exact(f"{label}: confidence", spec, {"base"}, {"raised", "raise_when", "raise_reason"})
    base = spec["base"]
    if base not in CONFIDENCE_LEVELS:
        raise ValueError(f"{label}: confidence.base must be one of {', '.join(CONFIDENCE_LEVELS)}")
    raised = spec.get("raised")
    if raised is None:
        if "raise_when" in spec or "raise_reason" in spec:
            raise ValueError(f"{label}: raise_when/raise_reason need 'raised'")
        return ConfidenceSpec(base, None, None, "")
    if raised not in CONFIDENCE_LEVELS or CONFIDENCE_LEVELS.index(raised) <= \
            CONFIDENCE_LEVELS.index(base):
        raise ValueError(f"{label}: confidence.raised must be a level above the base")
    conditions.validate_condition(spec.get("raise_when"), f"{label}: confidence.raise_when")
    return ConfidenceSpec(base, raised, spec["raise_when"],
                          _text(f"{label}: confidence", spec, "raise_reason"))


def load_mappings(path: Union[str, Path], dataset: AttackDataset) -> tuple[
        tuple[MappingRule, ...], tuple[NotMapped, ...], dict[str, Any], dict[str, str]]:
    """Load and validate mapping definitions against ``dataset``."""
    label = Path(path).name
    data = _read(Path(path), label)
    _exact(label, data, {"mapping_definition", "confidence_scale", "rules", "not_mapped"})

    definition = data["mapping_definition"]
    _exact(f"{label}: mapping_definition", definition,
           {"version", "reviewed_against", "description"})
    for key in ("version", "reviewed_against", "description"):
        _text(f"{label}: mapping_definition", definition, key)
    version = dataset.metadata["attack_version"]
    if f"v{version}" not in definition["reviewed_against"]:
        raise ValueError(
            f"{label}: reviewed against {definition['reviewed_against']!r} but the dataset is "
            f"ATT&CK v{version}; re-review the mappings and update 'reviewed_against'")

    scale = data["confidence_scale"]
    if not isinstance(scale, dict) or set(scale) != set(CONFIDENCE_LEVELS) \
            or not all(isinstance(v, str) and v.strip() for v in scale.values()):
        raise ValueError(f"{label}: 'confidence_scale' must describe exactly "
                         f"{', '.join(CONFIDENCE_LEVELS)}")

    rules: list[MappingRule] = []
    if not isinstance(data["rules"], list) or not data["rules"]:
        raise ValueError(f"{label}: 'rules' must be a non-empty list")
    keys = {"id", "rule_id", "technique_id", "tactic_id", "tactic_reason", "conditions",
            "evidence", "iocs", "confidence", "rationale", "limitations"}
    seen: set[str] = set()
    for item in data["rules"]:
        rid = item.get("id") if isinstance(item, dict) else None
        at = f"{label}: rule {rid!r}"
        if not isinstance(item, dict):
            raise ValueError(f"{label}: every rule must be an object")
        _exact(at, item, keys)
        for key in ("id", "rule_id", "technique_id", "tactic_id", "tactic_reason",
                    "rationale", "limitations"):
            _text(at, item, key)
        if rid in seen:
            raise ValueError(f"{at}: duplicate rule id")
        seen.add(rid)
        technique = dataset.techniques.get(item["technique_id"])
        if technique is None:
            raise ValueError(f"{at}: technique {item['technique_id']} is not in the dataset")
        if not technique.used_by_mappings:
            raise ValueError(f"{at}: the dataset marks {technique.id} as not used by mappings; "
                             "rebuild attack_subset.json for these mappings")
        if item["tactic_id"] not in technique.tactic_ids:
            raise ValueError(
                f"{at}: tactic {item['tactic_id']} is not a tactic of {technique.id} "
                f"(ATT&CK lists {', '.join(technique.tactic_ids)})")
        conditions.validate_condition(item["conditions"], f"{at}: conditions")
        conditions.validate_evidence(item["evidence"], at)
        conditions.validate_ioc_spec(item["iocs"], f"{at}: iocs")
        conditions.validate_template(item["rationale"], at)
        rules.append(MappingRule(
            rid, item["rule_id"], item["technique_id"], item["tactic_id"],
            item["tactic_reason"], item["conditions"], item["evidence"], item["iocs"],
            _confidence(at, item["confidence"]), item["rationale"], item["limitations"]))

    mapped_ids = {r.technique_id for r in rules}
    flagged = {t.id for t in dataset.techniques.values() if t.used_by_mappings}
    if flagged != mapped_ids:
        raise ValueError(f"{label}: the dataset's used_by_mappings flags {sorted(flagged)} do "
                         f"not match the mapped techniques {sorted(mapped_ids)}; rebuild "
                         "attack_subset.json")

    not_mapped: list[NotMapped] = []
    if not isinstance(data["not_mapped"], list):
        raise ValueError(f"{label}: 'not_mapped' must be a list")
    for item in data["not_mapped"]:
        at = f"{label}: not_mapped {item.get('technique_id') if isinstance(item, dict) else item!r}"
        if not isinstance(item, dict):
            raise ValueError(f"{label}: every not_mapped entry must be an object")
        _exact(at, item, {"technique_id", "reason"})
        tid = _text(at, item, "technique_id")
        if tid not in dataset.techniques:
            raise ValueError(f"{at}: technique is not in the dataset")
        if tid in mapped_ids:
            raise ValueError(f"{at}: technique is both mapped and listed as not mapped")
        not_mapped.append(NotMapped(tid, _text(at, item, "reason")))
    return tuple(rules), tuple(not_mapped), dict(definition), dict(scale)


def load_catalog(attack_path: Union[str, Path, None] = None,
                 mappings_path: Union[str, Path, None] = None) -> MappingCatalog:
    """Load the packaged catalog (or the given files) and validate everything."""
    dataset = load_dataset(attack_path or DEFAULT_ATTACK_PATH)
    rules, not_mapped, definition, scale = load_mappings(
        mappings_path or DEFAULT_MAPPINGS_PATH, dataset)
    return MappingCatalog(dataset, rules, not_mapped, definition, scale)
