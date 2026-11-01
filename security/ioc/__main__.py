"""Command-line IOC extraction.

    python -m security.ioc <evidence_folder> [options]

Options:
    --config FILE       detection settings (JSON), as for python -m security.detection
    --ioc-config FILE   IOC settings (JSON), e.g. {"ip_classes": ["public"]}
    --now ISO           analysis time for the findings (UTC), for reproducible JSON
    --json              print the full result as JSON

Runs validation, normalization, timeline and detection first, then extracts
the IOCs of the evidence the findings cite. Exit codes: 0 ran, 1 evidence
failed validation, 2 invalid option or configuration. Read-only; ASCII output.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from security.detection import DetectionConfig
from security.ioc import IocConfig, extract_case_iocs
from security.ioc.report import format_iocs
from security.utils.helpers import parse_timestamp
from security.validation import EvidenceNotValidError
from security.validation.report import format_report


def _fail(message: str) -> int:
    print(f"error: {message}", file=sys.stderr)
    return 2


def _load(path: Path, builder, label: str):
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ValueError(f"cannot read {label} {path}: {exc}") from None
    try:
        return builder(data)
    except ValueError as exc:
        raise ValueError(f"invalid {label}: {exc}") from None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m security.ioc",
        description="Extract IOCs from the evidence cited by detection findings (read-only).")
    parser.add_argument("folder", type=Path, help="evidence folder, e.g. INC-001")
    parser.add_argument("--config", type=Path, help="detection settings (JSON)")
    parser.add_argument("--ioc-config", type=Path, help="IOC settings (JSON)")
    parser.add_argument("--now", help="analysis time, ISO 8601 with timezone")
    parser.add_argument("--json", action="store_true", help="print JSON")
    args = parser.parse_args(argv)

    try:
        detection_config = (_load(args.config, DetectionConfig.from_dict, "configuration")
                            if args.config else None)
        ioc_config = (_load(args.ioc_config, IocConfig.from_dict, "IOC configuration")
                      if args.ioc_config else None)
    except ValueError as exc:
        return _fail(str(exc))
    try:
        now = parse_timestamp(args.now) if args.now else None
    except ValueError as exc:
        return _fail(f"invalid --now: {exc}")

    try:
        result = extract_case_iocs(args.folder, detection_config, ioc_config, now)
    except EvidenceNotValidError as exc:
        print("Evidence failed validation; IOC extraction was not run.\n")
        print(format_report(exc.result))
        return 1

    text = (json.dumps(result.to_dict(), indent=2) if args.json else format_iocs(result))
    try:
        print(text)
        sys.stdout.flush()
    except BrokenPipeError:  # e.g. `... | head`: not an error
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
    return 0


if __name__ == "__main__":
    sys.exit(main())
