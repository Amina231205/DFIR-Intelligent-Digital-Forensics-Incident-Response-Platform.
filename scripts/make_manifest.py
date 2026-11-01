"""DEV-ONLY: build ``manifest.json`` for a folder of evidence files.

In production the manifest is produced by the evidence-preservation module
(the teammate's side of the contract). This script exists so our synthetic
sample cases carry a valid manifest too, and can be re-run after editing a
sample file.

Usage:
    python scripts/make_manifest.py security/sample_evidence/INC-001
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from security.models.schemas import (  # noqa: E402
    MANIFEST_FILENAME,
    SCHEMA_VERSION,
    EvidenceSource,
)
from security.utils.helpers import load_json, sha256_file  # noqa: E402


def build_manifest(folder: Path) -> dict:
    """Describe every known evidence file found in ``folder``."""
    entries = []
    case_id = device = created_at = collector = None
    for source in EvidenceSource:
        path = folder / f"{source.value}.json"
        if not path.exists():
            continue
        data = load_json(path)
        case_id = case_id or data.get("case_id")
        device = device or data.get("device")
        created_at = created_at or data.get("collected_at")
        collector = collector or data.get("collector")
        entries.append({
            "name": path.name,
            "sha256": sha256_file(path),
            "size_bytes": path.stat().st_size,
            "record_count": len(data.get("records", [])),
        })
    return {
        "schema_version": SCHEMA_VERSION,
        "case_id": case_id,
        "device": device,
        "hash_algorithm": "SHA-256",
        "created_at": created_at,
        "collector": collector,
        "files": entries,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("folder", type=Path, help="evidence folder")
    args = parser.parse_args()
    manifest = build_manifest(args.folder)
    target = args.folder / MANIFEST_FILENAME
    target.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {target} ({len(manifest['files'])} files hashed)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
