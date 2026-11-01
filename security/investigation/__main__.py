"""CLI for the Phase 8 investigation engine."""
from __future__ import annotations

import argparse
from pathlib import Path

from security.investigation import investigate_case, investigation_to_json
from security.validation.validator import EvidenceNotValidError


def main() -> int:
    parser = argparse.ArgumentParser(description="Analyze a Sentinel DFIR evidence case.")
    parser.add_argument("evidence_dir", help="Directory containing the evidence JSON files and manifest.")
    parser.add_argument("--output", "-o", help="Write JSON output to this path instead of stdout.")
    args = parser.parse_args()
    try:
        result = investigate_case(args.evidence_dir)
    except EvidenceNotValidError as exc:
        parser.exit(2, f"Evidence validation failed: {exc}\n")
    output = investigation_to_json(result) + "\n"
    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
    else:
        print(output, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
