"""Command-line detection.

    python -m security.detection <evidence_folder> [options]

Options:
    --config FILE   JSON file with settings to override, e.g.
                    {"brute_force": {"threshold": 3, "window_seconds": 60}}
    --rule ID       run only this rule (repeat for several): DET-001 DET-002 DET-003
    --now ISO       analysis time (UTC, e.g. 2026-10-09T12:00:00Z); makes the
                    JSON output byte-for-byte reproducible
    --json          print the full result as JSON

Exit codes: 0 = ran (findings are results, not errors), 1 = evidence failed
validation, 2 = invalid option / configuration. Read-only.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from security.detection import (
    RULE_IDS, DetectionConfig, detect_case, format_detection)
from security.utils.helpers import parse_timestamp
from security.validation import EvidenceNotValidError
from security.validation.report import format_report


def _fail(message: str) -> int:
    print(f"error: {message}", file=sys.stderr)
    return 2


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m security.detection",
        description="Run the detection rules on an evidence folder (read-only).")
    parser.add_argument("folder", type=Path, help="evidence folder, e.g. INC-001")
    parser.add_argument("--config", type=Path, help="JSON settings file")
    parser.add_argument("--rule", dest="rules", action="append", metavar="ID")
    parser.add_argument("--now", help="analysis time, ISO 8601 with timezone")
    parser.add_argument("--json", action="store_true", help="print JSON")
    args = parser.parse_args(argv)

    config = None
    if args.config is not None:
        try:
            data = json.loads(args.config.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            return _fail(f"cannot read configuration {args.config}: {exc}")
        try:
            config = DetectionConfig.from_dict(data)
        except ValueError as exc:
            return _fail(f"invalid configuration: {exc}")

    unknown = sorted(set(args.rules or []) - set(RULE_IDS))
    if unknown:
        return _fail(f"unknown rule id(s) {unknown}; available: {', '.join(RULE_IDS)}")
    try:
        now = parse_timestamp(args.now) if args.now else None
    except ValueError as exc:
        return _fail(f"invalid --now: {exc}")

    try:
        result = detect_case(args.folder, config=config, rule_ids=args.rules, now=now)
    except EvidenceNotValidError as exc:
        print("Evidence failed validation; detection was not run.\n")
        print(format_report(exc.result))
        return 1

    text = (json.dumps(result.to_dict(), indent=2) if args.json
            else format_detection(result))
    try:
        print(text)
        sys.stdout.flush()
    except BrokenPipeError:  # e.g. `... | head`: not an error
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
    return 0


if __name__ == "__main__":
    sys.exit(main())
