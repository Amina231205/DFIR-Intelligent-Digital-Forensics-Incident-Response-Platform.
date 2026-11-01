"""Command-line entry point for the analysis module.

Phase 1: prints an inventory of an evidence folder (files, record counts,
case and device) so we can confirm the Evidence JSON contract is readable.
Later phases extend this into the full pipeline:

    validate -> normalize -> timeline -> detect -> IOCs -> MITRE -> investigate

Usage:
    python -m security.main --evidence security/sample_evidence/INC-001
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from security.models.schemas import (
    MANIFEST_FILENAME,
    OPTIONAL_SOURCES,
    REQUIRED_SOURCES,
)
from security.utils.helpers import load_json

DEFAULT_EVIDENCE_DIR = Path(__file__).parent / "sample_evidence" / "INC-001"


def summarize_folder(folder: Path) -> list[str]:
    """Return human-readable inventory lines for an evidence folder."""
    lines: list[str] = []
    case_id = device = None

    for source in (*REQUIRED_SOURCES, *OPTIONAL_SOURCES):
        path = folder / f"{source.value}.json"
        tag = "required" if source in REQUIRED_SOURCES else "optional"
        if not path.exists():
            lines.append(f"  [MISSING] {path.name:<16} ({tag})")
            continue
        data = load_json(path)
        case_id = case_id or data.get("case_id")
        device = device or data.get("device")
        count = len(data.get("records", []))
        lines.append(f"  [OK]      {path.name:<16} {count:>3} records ({tag})")

    manifest_state = "present" if (folder / MANIFEST_FILENAME).exists() else "MISSING"
    lines.append(f"  [{manifest_state.upper():<7}] {MANIFEST_FILENAME}")

    header = [
        f"Evidence folder : {folder}",
        f"Case ID         : {case_id}",
        f"Device          : {device}",
        "Files:",
    ]
    return header + lines


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Sentinel DFIR analysis module")
    parser.add_argument(
        "--evidence", type=Path, default=DEFAULT_EVIDENCE_DIR,
        help="folder containing the collector's evidence JSON files",
    )
    args = parser.parse_args(argv)

    if not args.evidence.is_dir():
        print(f"error: evidence folder not found: {args.evidence}", file=sys.stderr)
        return 2

    print("\n".join(summarize_folder(args.evidence)))
    print("\n(Phase 1 only: validation and analysis arrive in later phases.)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
