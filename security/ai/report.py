"""Human-readable formatter for the separate, validated AI result."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from security.ai.service import AIServiceResult


def _references(support: Mapping[str, Any]) -> str:
    parts = []
    for field, label in (
        ("finding_ids", "Findings"),
        ("event_ids", "Events"),
        ("ioc_ids", "IOCs"),
        ("attack_ids", "ATT&CK"),
    ):
        values = support[field]
        if values:
            parts.append(f"{label}: {', '.join(values)}")
    evidence_ids = [ref["evidence_id"] for ref in support["evidence_refs"]]
    if evidence_ids:
        parts.append(f"Evidence: {', '.join(evidence_ids)}")
    return "; ".join(parts) if parts else "No references"


def _section(title: str, items: list[Mapping[str, Any]], text_field: str) -> list[str]:
    lines = [f"{title}:"]
    if not items:
        lines.append("  (none)")
        return lines
    for item in items:
        lines.append(f"  - {item[text_field]}")
        support = item["supporting_evidence"]
        lines.append(f"    References: {_references(support)}")
        if "verification_status" in item:
            lines.append(f"    Status: {item['verification_status']}")
        if "confidence" in item:
            lines.append(
                f"    Confidence: {item['confidence']['level']} — "
                f"{item['confidence']['justification']}"
            )
        if "status" in item:
            lines.append(f"    Status: {item['status']} ({item['classification']})")
    return lines


def format_ai_report(result: AIServiceResult) -> str:
    """Format a validated AI result without rendering its input evidence."""
    analysis = result["analysis"]
    lines = ["MOCK/DEMO — NOT REAL LLM ANALYSIS", ""]
    lines.extend(_section("Confirmed Facts", analysis["confirmed_facts"], "statement"))
    lines.append("")
    lines.extend(_section("Observations", analysis["observations"], "statement"))
    lines.append("")
    lines.extend(_section("Hypotheses", analysis["hypotheses"], "statement"))
    lines.append("")
    lines.extend(_section("Recommendations", analysis["recommendations"], "action"))
    return "\n".join(lines)
