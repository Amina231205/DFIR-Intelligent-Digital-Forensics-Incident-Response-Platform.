"""Human-readable text report for a ValidationResult (used by the CLI)."""

from __future__ import annotations

from security.models.schemas import ValidationResult


def format_report(result: ValidationResult) -> str:
    """Render a result as plain text."""
    status = "VALID" if result.valid else "INVALID"
    lines = [
        f"Validation result : {status} "
        f"({len(result.errors)} errors, {len(result.warnings)} warnings)",
        f"Evidence folder   : {result.folder}",
        f"Case ID           : {result.case_id or '-'}",
        f"Device            : {result.device or '-'}",
        f"Checked files     : {', '.join(result.checked_files) or '-'}",
    ]
    for title, issues in (("ERRORS", result.errors), ("WARNINGS", result.warnings)):
        if issues:
            lines += ["", f"{title}:"]
            lines += [f"  [{i.code}] {i.message}" for i in issues]
    return "\n".join(lines)
