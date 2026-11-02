"""CLI for the Phase 8 investigation engine."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from security.ai import (
    AIContractValidationError,
    AIProviderError,
    MockProvider,
    analyze_investigation,
)
from security.ai.report import format_ai_report
from security.investigation import investigate_case, investigation_to_json
from security.validation.validator import EvidenceNotValidError


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Analyze a Sentinel DFIR evidence case.")
    parser.add_argument("evidence_dir", help="Directory containing the evidence JSON files and manifest.")
    parser.add_argument("--output", "-o", help="Write JSON output to this path instead of stdout.")
    parser.add_argument(
        "--ai-provider",
        choices=("mock",),
        help="Run optional AI-assisted analysis using the local mock provider.",
    )
    args = parser.parse_args(argv)
    try:
        result = investigate_case(args.evidence_dir)
    except EvidenceNotValidError as exc:
        if args.ai_provider:
            parser.exit(2, "Evidence validation failed; no AI analysis was run.\n")
        parser.exit(2, f"Evidence validation failed: {exc}\n")

    output = investigation_to_json(result) + "\n"
    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
    else:
        print(output, end="")

    if args.ai_provider == "mock":
        try:
            ai_result = analyze_investigation(result, MockProvider())
            print(format_ai_report(ai_result), file=sys.stderr)
        except AIContractValidationError:
            print(
                "AI response was rejected; deterministic investigation output is available.",
                file=sys.stderr,
            )
            return 3
        except AIProviderError:
            print(
                "AI analysis failed; deterministic investigation output is available.",
                file=sys.stderr,
            )
            return 3
        except Exception:
            # Never expose exception strings or chained provider details on the CLI.
            print(
                "AI analysis failed; deterministic investigation output is available.",
                file=sys.stderr,
            )
            return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
