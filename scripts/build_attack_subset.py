"""DEV-ONLY: build ``security/mitre/attack_subset.json`` from an official
MITRE ATT&CK Enterprise STIX bundle.

The analysis engine never uses the network. This script is how the curated
subset is (re)generated, so the dataset used by the project is identifiable:
the output records the ATT&CK version, the bundle's SHA-256, its source URL and
the retrieval time. Nothing is invented: every name, tactic and relationship is
read from the bundle, and the script fails if a referenced technique is
missing, revoked or deprecated.

The subset contains: every technique/sub-technique referenced by
``mappings.json`` (rules and ``not_mapped``), their parent techniques, and all
tactics. It is NOT the full ATT&CK matrix.

Usage:
    python scripts/build_attack_subset.py --bundle enterprise-attack.json \\
        --source-url <URL of the bundle, default: the attack-stix-data repository> \\
        --retrieved-utc 2026-10-12T22:09:13Z

    # or download it first (needs network):
    python scripts/build_attack_subset.py --download --bundle /tmp/enterprise-attack.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_URL = ("https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
               "master/enterprise-attack/enterprise-attack.json")
DEFAULT_MAPPINGS = ROOT / "security" / "mitre" / "mappings.json"
DEFAULT_OUT = ROOT / "security" / "mitre" / "attack_subset.json"


def _attack_id(obj: dict[str, Any]) -> tuple[str, str] | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref["external_id"], ref.get("url", "")
    return None


def referenced_technique_ids(mappings: dict[str, Any]) -> set[str]:
    ids = {rule["technique_id"] for rule in mappings["rules"]}
    ids |= {item["technique_id"] for item in mappings.get("not_mapped", [])}
    return ids


def build_subset(bundle: dict[str, Any], wanted: set[str], used: set[str],
                 metadata: dict[str, Any]) -> dict[str, Any]:
    objects = bundle["objects"]
    collection = next(o for o in objects if o["type"] == "x-mitre-collection")

    tactics: dict[str, dict[str, Any]] = {}            # shortname -> tactic
    for obj in objects:
        if obj["type"] == "x-mitre-tactic" and not obj.get("revoked") \
                and not obj.get("x_mitre_deprecated"):
            attack_id, url = _attack_id(obj)
            tactics[obj["x_mitre_shortname"]] = {
                "id": attack_id, "name": obj["name"],
                "shortname": obj["x_mitre_shortname"], "url": url}

    by_attack_id: dict[str, dict[str, Any]] = {}
    by_stix_id: dict[str, dict[str, Any]] = {}
    for obj in objects:
        if obj["type"] == "attack-pattern":
            found = _attack_id(obj)
            if found:
                by_attack_id[found[0]] = obj
                by_stix_id[obj["id"]] = obj
    parent_of = {o["source_ref"]: o["target_ref"] for o in objects
                 if o["type"] == "relationship" and o["relationship_type"] == "subtechnique-of"}

    needed: set[str] = set()
    for technique_id in wanted:
        if technique_id not in by_attack_id:
            raise SystemExit(f"error: {technique_id} is not in the ATT&CK bundle")
        needed.add(technique_id)
        parent = parent_of.get(by_attack_id[technique_id]["id"])
        if parent:
            needed.add(_attack_id(by_stix_id[parent])[0])

    techniques = []
    for technique_id in sorted(needed):
        obj = by_attack_id[technique_id]
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            raise SystemExit(f"error: {technique_id} is revoked or deprecated in this bundle")
        parent = parent_of.get(obj["id"])
        phases = [p["phase_name"] for p in obj.get("kill_chain_phases", [])
                  if p["kill_chain_name"] == "mitre-attack"]
        techniques.append({
            "id": technique_id,
            "name": obj["name"],
            "is_subtechnique": bool(obj.get("x_mitre_is_subtechnique")),
            "parent_id": _attack_id(by_stix_id[parent])[0] if parent else None,
            "tactics": sorted(tactics[p]["id"] for p in phases),
            "url": _attack_id(obj)[1],
            "version": obj.get("x_mitre_version"),
            "modified": obj["modified"][:10],
            "used_by_mappings": technique_id in used,
        })

    metadata = {
        **metadata,
        "attack_version": collection["x_mitre_version"],
        "attack_spec_version": collection["x_mitre_attack_spec_version"],
        "collection_modified": collection["modified"],
        "kind": "curated subset",
        "technique_count": len(techniques),
        "coverage_note": ("Curated subset: only the techniques referenced by mappings.json, "
                          "their parent techniques and all tactics. It is NOT the full "
                          "ATT&CK matrix and must not be read as coverage of it."),
    }
    return {
        "metadata": metadata,
        "tactics": sorted(tactics.values(), key=lambda t: t["id"]),
        "techniques": techniques,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--bundle", type=Path, required=True,
                        help="path of the ATT&CK Enterprise STIX bundle (JSON)")
    parser.add_argument("--download", action="store_true",
                        help="download the bundle to --bundle first (needs network)")
    parser.add_argument("--source-url", default=DEFAULT_URL)
    parser.add_argument("--retrieved-utc",
                        help="retrieval time to record (default: now, UTC)")
    parser.add_argument("--mappings", type=Path, default=DEFAULT_MAPPINGS)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()

    if args.download:
        urllib.request.urlretrieve(args.source_url, args.bundle)
    raw = args.bundle.read_bytes()
    bundle = json.loads(raw.decode("utf-8"))
    mappings = json.loads(args.mappings.read_text(encoding="utf-8"))
    used = {rule["technique_id"] for rule in mappings["rules"]}
    retrieved = args.retrieved_utc or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    subset = build_subset(
        bundle, referenced_technique_ids(mappings), used,
        {"dataset": "MITRE ATT&CK Enterprise", "source_url": args.source_url,
         "source_sha256": hashlib.sha256(raw).hexdigest(), "retrieved_utc": retrieved,
         "generated_by": "scripts/build_attack_subset.py"})
    args.out.write_text(json.dumps(subset, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    print(f"wrote {args.out}: ATT&CK {subset['metadata']['attack_version']}, "
          f"{len(subset['techniques'])} techniques, {len(subset['tactics'])} tactics")
    return 0


if __name__ == "__main__":
    sys.exit(main())
