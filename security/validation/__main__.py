"""Command-line validator.

    python -m security.validation <evidence_folder> [--json]

Exit code: 0 = valid (warnings allowed), 1 = invalid.
The folder is only read, never modified.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from security.validation import validate_case
from security.validation.report import format_report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m security.validation",
        description="Validate a collector evidence folder (read-only).",
    )
    parser.add_argument("folder", type=Path, help="evidence folder, e.g. INC-001")
    parser.add_argument("--json", action="store_true",
                        help="print the result as JSON instead of text")
    args = parser.parse_args(argv)

    result = validate_case(args.folder)
    text = (json.dumps(result.to_dict(), indent=2) if args.json
            else format_report(result))
    try:
        print(text)
        sys.stdout.flush()
    except BrokenPipeError:  # e.g. `... | head -1`: not an error
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
    return 0 if result.valid else 1


if __name__ == "__main__":
    sys.exit(main())
