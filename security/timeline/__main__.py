"""Command-line timeline.

    python -m security.timeline <evidence_folder> [filters] [--json] [--limit N]

Filters (all optional, combined with AND; repeat a flag for OR):
    --start ISO --end ISO     inclusive UTC range, e.g. 2026-10-08T07:31:00Z
    --type NAME               event type, e.g. logon_failed
    --source NAME             evidence source, e.g. processes
    --user NAME               user (case-insensitive)
    --device NAME             device (case-insensitive)

Validates first; invalid evidence prints the validation report and exits 1.
Bad filter values exit 2. Read-only.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from security.timeline import build_case_timeline, filter_timeline, format_timeline
from security.validation import EvidenceNotValidError
from security.validation.report import format_report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m security.timeline",
        description="Validate, normalize and print the incident timeline (read-only).",
    )
    parser.add_argument("folder", type=Path, help="evidence folder, e.g. INC-001")
    parser.add_argument("--start", help="inclusive start, ISO 8601 with timezone")
    parser.add_argument("--end", help="inclusive end, ISO 8601 with timezone")
    parser.add_argument("--type", dest="types", action="append", metavar="NAME")
    parser.add_argument("--source", dest="sources", action="append", metavar="NAME")
    parser.add_argument("--user", dest="users", action="append", metavar="NAME")
    parser.add_argument("--device", dest="devices", action="append", metavar="NAME")
    parser.add_argument("--json", action="store_true",
                        help="print the timeline as JSON")
    parser.add_argument("--limit", type=int, default=0,
                        help="rows to print in text mode (0 = all, default)")
    args = parser.parse_args(argv)

    try:
        timeline = build_case_timeline(args.folder)
    except EvidenceNotValidError as exc:
        print("Evidence failed validation; no timeline was built.\n")
        print(format_report(exc.result))
        return 1

    try:
        timeline = filter_timeline(
            timeline, start=args.start, end=args.end, event_types=args.types,
            sources=args.sources, users=args.users, devices=args.devices)
    except ValueError as exc:
        print(f"error: invalid filter: {exc}", file=sys.stderr)
        return 2

    text = (json.dumps(timeline.to_dict(), indent=2) if args.json
            else format_timeline(timeline, args.limit))
    try:
        print(text)
        sys.stdout.flush()
    except BrokenPipeError:  # e.g. `... | head`: not an error
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
    return 0


if __name__ == "__main__":
    sys.exit(main())
