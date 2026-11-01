"""Command-line normalizer.

    python -m security.normalization <evidence_folder> [--json] [--limit N]

Validates first; invalid evidence prints the validation report and exits 1.
Read-only. ``--limit 0`` prints every event.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter
from pathlib import Path

from security.models.schemas import NormalizationResult
from security.normalization import normalize_case
from security.utils.helpers import format_timestamp
from security.validation import EvidenceNotValidError
from security.validation.report import format_report


def format_summary(result: NormalizationResult, limit: int) -> str:
    """Plain-text overview: counts by type, then the first events."""
    counts = Counter(e.event_type.value for e in result.events)
    lines = [
        f"Case ID : {result.case_id}",
        f"Device  : {result.device}",
        f"Events  : {len(result.events)} "
        f"(users.json -> {len(result.users)} enrichment records, "
        "system.json -> host context; neither is a timeline event)",
        "",
        "Events by type:",
    ]
    lines += [f"  {name:<20} {count}" for name, count in sorted(counts.items())]
    shown = result.events if limit == 0 else result.events[:limit]
    lines += ["", f"Events {'(all)' if limit == 0 else f'(first {len(shown)})'}:"]
    for event in shown:
        lines.append(
            f"  {event.event_id}  {format_timestamp(event.timestamp)}  "
            f"{event.event_type.value:<19} {event.evidence_id:<10} "
            f"user={event.user or '-'}")
    if result.warnings:
        lines += ["", f"Normalization warnings ({len(result.warnings)}):"]
        lines += [f"  [{w.code}] {w.message}" for w in result.warnings]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m security.normalization",
        description="Validate and normalize a collector evidence folder (read-only).",
    )
    parser.add_argument("folder", type=Path, help="evidence folder, e.g. INC-001")
    parser.add_argument("--json", action="store_true",
                        help="print the full result as JSON")
    parser.add_argument("--limit", type=int, default=10,
                        help="events to list in text mode (0 = all, default 10)")
    args = parser.parse_args(argv)

    try:
        result = normalize_case(args.folder)
    except EvidenceNotValidError as exc:
        print("Evidence failed validation; nothing was normalized.\n")
        print(format_report(exc.result))
        return 1

    text = (json.dumps(result.to_dict(), indent=2) if args.json
            else format_summary(result, args.limit))
    try:
        print(text)
        sys.stdout.flush()
    except BrokenPipeError:  # e.g. `... | head`: not an error
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
    return 0


if __name__ == "__main__":
    sys.exit(main())
