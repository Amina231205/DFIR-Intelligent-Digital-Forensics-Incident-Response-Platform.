"""Command-line ATT&CK mapping.

    python -m security.mitre <evidence_folder> [options]
    python -m security.mitre --list

Options:
    --config FILE       detection settings (JSON), as for python -m security.detection
    --ioc-config FILE   IOC settings (JSON), as for python -m security.ioc
    --now ISO           analysis time for the findings (UTC), for reproducible JSON
    --json              print the full result as JSON
    --list              print the supported mappings, the omissions, the dataset and the
                        confidence scale (no evidence folder needed)

Runs validation, normalization, timeline, detection and IOC extraction first,
then maps the findings. Exit codes: 0 ran, 1 evidence failed validation, 2
invalid option or configuration. Read-only; ASCII output; no network.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from security.detection import DetectionConfig
from security.ioc import IocConfig
from security.mitre import load_catalog, map_case
from security.mitre.report import format_catalog, format_mappings
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


def _emit(text: str) -> None:
    try:
        print(text)
        sys.stdout.flush()
    except BrokenPipeError:  # e.g. `... | head`: not an error
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m security.mitre",
        description="Map detection findings to MITRE ATT&CK (read-only, no network).")
    parser.add_argument("folder", type=Path, nargs="?", help="evidence folder, e.g. INC-001")
    parser.add_argument("--config", type=Path, help="detection settings (JSON)")
    parser.add_argument("--ioc-config", type=Path, help="IOC settings (JSON)")
    parser.add_argument("--now", help="analysis time, ISO 8601 with timezone")
    parser.add_argument("--json", action="store_true", help="print JSON")
    parser.add_argument("--list", action="store_true", help="print the supported mappings")
    args = parser.parse_args(argv)

    try:
        catalog = load_catalog()
    except ValueError as exc:
        return _fail(f"invalid ATT&CK data or mapping definitions: {exc}")
    if args.list:
        _emit(format_catalog(catalog))
        return 0
    if args.folder is None:
        return _fail("an evidence folder is required (or use --list)")

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
        result = map_case(args.folder, detection_config, ioc_config, now, catalog)
    except EvidenceNotValidError as exc:
        print("Evidence failed validation; ATT&CK mapping was not run.\n")
        print(format_report(exc.result))
        return 1
    _emit(json.dumps(result.to_dict(), indent=2) if args.json else format_mappings(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
