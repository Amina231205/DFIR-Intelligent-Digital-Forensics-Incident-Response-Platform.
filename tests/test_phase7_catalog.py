"""Phase 7 tests: ATT&CK dataset, mapping definitions and their validation."""

from __future__ import annotations

import json
import re
import shutil
from pathlib import Path

import pytest

from security.mitre import load_catalog
from security.mitre.catalog import DEFAULT_ATTACK_PATH, DEFAULT_MAPPINGS_PATH

MITRE_DIR = Path(__file__).resolve().parents[1] / "security" / "mitre"

# Copied from the official ATT&CK Enterprise v19.2 STIX bundle (see docs/ATTACK_MAPPING.md).
TACTICS = {
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Stealth",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0010": "Exfiltration",
    "TA0011": "Command and Control",
    "TA0040": "Impact",
    "TA0042": "Resource Development",
    "TA0043": "Reconnaissance",
    "TA0112": "Defense Impairment",
}
TECHNIQUES = {  # id: (name, parent, tactics, used by a mapping)
    "T1021": ("Remote Services", None, ("TA0008",), False),
    "T1021.001": ("Remote Desktop Protocol", "T1021", ("TA0008",), False),
    "T1027": ("Obfuscated Files or Information", None, ("TA0005",), False),
    "T1027.010": ("Command Obfuscation", "T1027", ("TA0005",), True),
    "T1059": ("Command and Scripting Interpreter", None, ("TA0002",), False),
    "T1059.001": ("PowerShell", "T1059", ("TA0002",), True),
    "T1059.005": ("Visual Basic", "T1059", ("TA0002",), False),
    "T1071": ("Application Layer Protocol", None, ("TA0011",), False),
    "T1071.001": ("Web Protocols", "T1071", ("TA0011",), False),
    "T1078": ("Valid Accounts", None, ("TA0001", "TA0003", "TA0004", "TA0005"), False),
    "T1078.003": ("Local Accounts", "T1078", ("TA0001", "TA0003", "TA0004", "TA0005"), False),
    "T1098": ("Account Manipulation", None, ("TA0003", "TA0004"), False),
    "T1098.007": ("Additional Local or Domain Groups", "T1098", ("TA0003", "TA0004"), True),
    "T1105": ("Ingress Tool Transfer", None, ("TA0011",), True),
    "T1110": ("Brute Force", None, ("TA0006",), True),
    "T1110.001": ("Password Guessing", "T1110", ("TA0006",), True),
    "T1110.003": ("Password Spraying", "T1110", ("TA0006",), False),
    "T1133": ("External Remote Services", None, ("TA0001", "TA0003"), False),
    "T1136": ("Create Account", None, ("TA0003",), True),
    "T1136.001": ("Local Account", "T1136", ("TA0003",), True),
    "T1140": ("Deobfuscate/Decode Files or Information", None, ("TA0005",), False),
    "T1204": ("User Execution", None, ("TA0002",), False),
    "T1204.002": ("Malicious File", "T1204", ("TA0002",), False),
}
# rule id: (detection rule, technique, display name, tactic id)
RULES = {
    "DET001-T1110.001": ("DET-001", "T1110.001", "Brute Force: Password Guessing", "TA0006"),
    "DET001-T1110": ("DET-001", "T1110", "Brute Force", "TA0006"),
    "DET002-T1059.001": (
        "DET-002",
        "T1059.001",
        "Command and Scripting Interpreter: PowerShell",
        "TA0002",
    ),
    "DET002-T1027.010": (
        "DET-002",
        "T1027.010",
        "Obfuscated Files or Information: Command Obfuscation",
        "TA0005",
    ),
    "DET002-T1105": ("DET-002", "T1105", "Ingress Tool Transfer", "TA0011"),
    "DET003-T1136.001": ("DET-003", "T1136.001", "Create Account: Local Account", "TA0003"),
    "DET003-T1136": ("DET-003", "T1136", "Create Account", "TA0003"),
    "DET003-T1098.007": (
        "DET-003",
        "T1098.007",
        "Account Manipulation: Additional Local or Domain Groups",
        "TA0004",
    ),
}
NOT_MAPPED = [
    "T1110.003",
    "T1078",
    "T1078.003",
    "T1021.001",
    "T1133",
    "T1059.005",
    "T1204.002",
    "T1071.001",
    "T1140",
]


class TestDataset:
    def test_dataset_is_identifiable(self):
        m = load_catalog().dataset.metadata
        assert m["dataset"] == "MITRE ATT&CK Enterprise"
        assert (m["attack_version"], m["attack_spec_version"]) == ("19.2", "3.3.0")
        assert m["source_url"].startswith(
            "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
        )
        assert m["source_sha256"] == (
            "dc1639caa5501d720e280cf1cbd8fbe009884a0c9b3e6e9ed9d0c25166c3d8f4"
        )
        assert m["retrieved_utc"] == "2026-10-12T22:09:13Z"
        assert m["kind"] == "curated subset" and m["technique_count"] == len(TECHNIQUES)

    def test_the_dataset_says_it_is_not_full_coverage(self):
        assert "NOT the full ATT&CK matrix" in load_catalog().dataset.metadata["coverage_note"]

    def test_tactics_are_exact(self):
        tactics = load_catalog().dataset.tactics
        assert {t.id: t.name for t in tactics.values()} == TACTICS

    def test_techniques_are_exact(self):
        techniques = load_catalog().dataset.techniques
        assert {
            t.id: (t.name, t.parent_id, t.tactic_ids, t.used_by_mappings)
            for t in techniques.values()
        } == TECHNIQUES

    def test_stealth_is_the_current_name_of_ta0005(self):
        # v19.2 renamed Defense Evasion; the data, not memory, is the source of names.
        assert load_catalog().dataset.tactics["TA0005"].name == "Stealth"

    def test_subtechniques_have_their_parent_and_display_names(self):
        dataset = load_catalog().dataset
        assert dataset.display_name("T1059.001") == "Command and Scripting Interpreter: PowerShell"
        assert dataset.display_name("T1105") == "Ingress Tool Transfer"
        for t in dataset.techniques.values():
            assert t.is_subtechnique == bool(t.parent_id) == ("." in t.id)

    def test_every_technique_has_an_attack_url(self):
        for t in load_catalog().dataset.techniques.values():
            assert t.url.startswith("https://attack.mitre.org/techniques/" + t.id.split(".")[0])


class TestMappingDefinitions:
    def test_supported_rules_are_exact(self):
        catalog = load_catalog()
        assert {
            r.id: (
                r.rule_id,
                r.technique_id,
                catalog.dataset.display_name(r.technique_id),
                r.tactic_id,
            )
            for r in catalog.rules
        } == RULES

    def test_every_tactic_belongs_to_its_technique(self):
        catalog = load_catalog()
        for rule in catalog.rules:
            assert rule.tactic_id in catalog.dataset.techniques[rule.technique_id].tactic_ids

    def test_tactic_names(self):
        catalog = load_catalog()
        names = {r.technique_id: catalog.dataset.tactics[r.tactic_id].name for r in catalog.rules}
        assert names == {
            "T1110.001": "Credential Access",
            "T1110": "Credential Access",
            "T1059.001": "Execution",
            "T1027.010": "Stealth",
            "T1105": "Command and Control",
            "T1136.001": "Persistence",
            "T1136": "Persistence",
            "T1098.007": "Privilege Escalation",
        }

    def test_the_omissions_are_recorded_with_reasons(self):
        catalog = load_catalog()
        assert [n.technique_id for n in catalog.not_mapped] == NOT_MAPPED
        assert all(len(n.reason) > 20 for n in catalog.not_mapped)
        assert not {n.technique_id for n in catalog.not_mapped} & set(
            catalog.supported_technique_ids()
        )

    def test_supported_techniques(self):
        assert load_catalog().supported_technique_ids() == sorted({v[1] for v in RULES.values()})

    def test_confidence_scale_is_documented(self):
        scale = load_catalog().confidence_scale
        assert set(scale) == {"Low", "Medium", "High"}
        assert "corroboration" in scale["High"] and "finding" in scale["Low"]

    def test_the_engine_contains_no_attack_knowledge(self):
        for name in ("mapper.py", "conditions.py"):
            assert not re.search(r"T1\d{3}", (MITRE_DIR / name).read_text(encoding="utf-8")), name

    def test_loading_modifies_nothing(self):
        before = {p: p.read_bytes() for p in (DEFAULT_ATTACK_PATH, DEFAULT_MAPPINGS_PATH)}
        load_catalog()
        assert {p: p.read_bytes() for p in before} == before

    def test_the_packaged_files_are_ascii(self):
        for path in (DEFAULT_ATTACK_PATH, DEFAULT_MAPPINGS_PATH):
            assert path.read_text(encoding="utf-8").isascii()


def copies(tmp_path):
    attack, mappings = tmp_path / "attack_subset.json", tmp_path / "mappings.json"
    shutil.copy(DEFAULT_ATTACK_PATH, attack)
    shutil.copy(DEFAULT_MAPPINGS_PATH, mappings)
    return attack, mappings


def rule(d, rule_id):
    return next(r for r in d["rules"] if r["id"] == rule_id)


DATASET_BREAKS = [
    ("missing metadata key", lambda d: d["metadata"].pop("attack_version"), "attack_version"),
    ("bad sha", lambda d: d["metadata"].update(source_sha256="abc"), "source_sha256"),
    ("bad time", lambda d: d["metadata"].update(retrieved_utc="yesterday"), "retrieved_utc"),
    (
        "duplicate technique",
        lambda d: d["techniques"].append(dict(d["techniques"][0])),
        "duplicate technique id",
    ),
    (
        "missing parent",
        lambda d: d.update(techniques=[t for t in d["techniques"] if t["id"] != "T1059"]),
        "is not in the dataset",
    ),
    ("unknown tactic", lambda d: d["techniques"][0].update(tactics=["TA9999"]), "known tactic ids"),
    ("sub flag", lambda d: d["techniques"][0].update(is_subtechnique=True), "is_subtechnique"),
    ("count", lambda d: d["metadata"].update(technique_count=99), "technique_count"),
    (
        "duplicate tactic",
        lambda d: d["tactics"].append(dict(d["tactics"][0])),
        "duplicate tactic id",
    ),
    ("unknown key", lambda d: d.update(extra=1), "unknown key"),
    ("no techniques", lambda d: d.update(techniques=[]), "non-empty list"),
]
MAPPING_BREAKS = [
    (
        "unknown technique",
        lambda d: rule(d, "DET001-T1110").update(technique_id="T9999"),
        "is not in the dataset",
    ),
    (
        "wrong tactic",
        lambda d: rule(d, "DET002-T1059.001").update(tactic_id="TA0006"),
        "is not a tactic of T1059.001",
    ),
    (
        "unknown check",
        lambda d: rule(d, "DET001-T1110").update(conditions={"check": "made_up"}),
        "unknown check",
    ),
    (
        "bad placeholder",
        lambda d: rule(d, "DET001-T1110").update(rationale="{oops}"),
        "unsupported placeholder",
    ),
    (
        "duplicate id",
        lambda d: rule(d, "DET001-T1110").update(id="DET001-T1110.001"),
        "duplicate rule id",
    ),
    (
        "overlap",
        lambda d: d["not_mapped"].append({"technique_id": "T1105", "reason": "x"}),
        "both mapped and listed",
    ),
    (
        "old review",
        lambda d: d["mapping_definition"].update(reviewed_against="ATT&CK v18.0"),
        "re-review",
    ),
    (
        "unflagged technique",
        lambda d: rule(d, "DET002-T1105").update(technique_id="T1059", tactic_id="TA0002"),
        "not used by mappings",
    ),
    (
        "bad base",
        lambda d: rule(d, "DET001-T1110").update(confidence={"base": "Certain"}),
        "confidence.base",
    ),
    (
        "raise not above base",
        lambda d: rule(d, "DET001-T1110")["confidence"].update(raised="Medium"),
        "level above the base",
    ),
    (
        "raise without condition",
        lambda d: rule(d, "DET001-T1110")["confidence"].pop("raise_when"),
        "must be an object",
    ),
    ("missing key", lambda d: rule(d, "DET001-T1110").pop("rationale"), "missing key"),
    ("unknown key", lambda d: rule(d, "DET001-T1110").update(extra=1), "unknown key"),
    (
        "bad evidence kind",
        lambda d: rule(d, "DET001-T1110").update(evidence=[{"events_from": "magic"}]),
        "events_from",
    ),
    ("no rules", lambda d: d.update(rules=[]), "non-empty list"),
    ("scale incomplete", lambda d: d["confidence_scale"].pop("Low"), "confidence_scale"),
    (
        "unknown omitted technique",
        lambda d: d["not_mapped"].append({"technique_id": "T9999", "reason": "x"}),
        "not in the dataset",
    ),
    (
        "condition typo",
        lambda d: rule(d, "DET001-T1110").update(
            conditions={"check": "context_equals", "pth": "k", "value": 1}
        ),
        "missing parameter",
    ),
]


class TestInvalidDefinitions:
    @pytest.mark.parametrize(
        "label, change, message", DATASET_BREAKS, ids=[b[0] for b in DATASET_BREAKS]
    )
    def test_broken_dataset(self, tmp_path, label, change, message):
        attack, mappings = copies(tmp_path)
        data = json.loads(attack.read_text(encoding="utf-8"))
        change(data)
        attack.write_text(json.dumps(data), encoding="utf-8")
        with pytest.raises(ValueError, match=message):
            load_catalog(attack, mappings)

    @pytest.mark.parametrize(
        "label, change, message", MAPPING_BREAKS, ids=[b[0] for b in MAPPING_BREAKS]
    )
    def test_broken_mappings(self, tmp_path, label, change, message):
        attack, mappings = copies(tmp_path)
        data = json.loads(mappings.read_text(encoding="utf-8"))
        change(data)
        mappings.write_text(json.dumps(data), encoding="utf-8")
        with pytest.raises(ValueError, match=message):
            load_catalog(attack, mappings)

    @pytest.mark.parametrize(
        "content, message",
        [("{ not json", "cannot read"), ("[]", "top level must be a JSON object")],
    )
    def test_unreadable_files(self, tmp_path, content, message):
        attack, mappings = copies(tmp_path)
        attack.write_text(content, encoding="utf-8")
        with pytest.raises(ValueError, match=message):
            load_catalog(attack, mappings)
        attack, mappings = copies(tmp_path)
        mappings.write_text(content, encoding="utf-8")
        with pytest.raises(ValueError, match=message):
            load_catalog(attack, mappings)

    def test_missing_file(self, tmp_path):
        with pytest.raises(ValueError, match="cannot read"):
            load_catalog(tmp_path / "nope.json")

    def test_errors_name_the_file(self, tmp_path):
        attack, mappings = copies(tmp_path)
        data = json.loads(mappings.read_text(encoding="utf-8"))
        data["rules"] = []
        mappings.write_text(json.dumps(data), encoding="utf-8")
        with pytest.raises(ValueError, match="mappings.json"):
            load_catalog(attack, mappings)
