"""CLI to analyze and persist a case in local SQLite storage."""
from __future__ import annotations

import argparse

from security.investigation import investigate_case
from security.storage import save_investigation
from security.validation.validator import EvidenceNotValidError


def main() -> int:
    parser = argparse.ArgumentParser(description="Analyze evidence and save the result to SQLite.")
    parser.add_argument("evidence_dir", help="Directory containing evidence JSON files and manifest.")
    parser.add_argument("--database", default="data/sentinel.sqlite", help="SQLite database path.")
    args = parser.parse_args()
    try:
        result = investigate_case(args.evidence_dir)
        status = save_investigation(args.database, result)
    except EvidenceNotValidError as exc:
        parser.exit(2, f"Evidence validation failed: {exc}\n")
    print(f"{status['status']}: case {status['case_id']} -> {args.database}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
