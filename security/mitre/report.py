"""Plain-text rendering of an ATT&CK mapping result (ASCII only)."""

from __future__ import annotations

from security.detection.report import ascii_safe
from security.mitre.catalog import MappingCatalog
from security.models.schemas import MitreMapping, MitreResult


def _dataset_line(dataset: dict) -> str:
    return (f"ATT&CK dataset : {dataset['dataset']} v{dataset['attack_version']} "
            f"(spec {dataset['attack_spec_version']}), {dataset['kind']}, "
            f"retrieved {dataset['retrieved_utc']}")


def _mapping_lines(mapping: MitreMapping) -> list[str]:
    head = f"{mapping.mapping_id}  {mapping.technique_id}  {mapping.technique_name}"
    lines = [head]
    if mapping.is_subtechnique:
        lines.append(f"    sub-technique {mapping.subtechnique_id} {mapping.subtechnique_name} "
                     f"of {mapping.parent_technique_id} {mapping.parent_technique_name}")
    other = [t["name"] for t in mapping.tactics if t["id"] != mapping.tactic_id]
    lines += [
        f"    tactic     : {mapping.tactic_id} {mapping.tactic}   confidence: "
        f"{mapping.confidence.value}" + (f"   (ATT&CK also lists: {', '.join(other)})"
                                         if other else ""),
        f"    findings   : {', '.join(mapping.related_findings)}",
        f"    events     : {', '.join(mapping.supporting_events) or '-'}",
        f"    records    : {', '.join(mapping.evidence_sources) or '-'}",
        f"    IOCs       : {', '.join(mapping.ioc_ids) or '-'}",
        f"    why        : {mapping.reason}",
        "    confidence because:",
        *[f"      - {factor}" for factor in mapping.confidence_factors],
    ]
    return lines


def format_mappings(result: MitreResult) -> str:
    """Render mappings, what was evaluated but not mapped, and data gaps."""
    lines = [
        _dataset_line(result.dataset),
        f"Mappings defn  : v{result.mapping_definition['version']} "
        f"({result.mapping_definition['reviewed_against']}), "
        f"{result.mapping_definition['rule_count']} rules",
        f"Case ID        : {result.case_id or '-'}",
        f"Mappings       : {len(result.mappings)}",
    ]
    for mapping in result.mappings:
        lines += ["", *_mapping_lines(mapping)]
    if not result.mappings:
        lines += ["", "No mappings. (Nothing was forced: see the evaluations and data gaps "
                      "below.)"]
    skipped = [e for e in result.evaluations if e.status != "mapped"]
    if skipped:
        lines += ["", "Evaluated but not mapped:"]
        for e in skipped:
            rule = e.mapping_rule_id or "-"
            lines.append(f"  {e.finding_id}  {rule:<18} {e.status}: {e.reason}")
    if result.data_gaps:
        lines += ["", "Data gaps (not negative results):"]
        lines += [f"  - {gap}" for gap in result.data_gaps]
    lines += ["", "Coverage: " + result.dataset["coverage_note"]]
    return ascii_safe("\n".join(lines))


def format_catalog(catalog: MappingCatalog) -> str:
    """Render the supported mappings, the omissions and the confidence scale."""
    dataset = catalog.dataset
    lines = [_dataset_line(dataset.metadata),
             f"Mappings defn  : v{catalog.definition['version']} "
             f"({catalog.definition['reviewed_against']})",
             f"Coverage       : {dataset.metadata['coverage_note']}",
             "", "Supported mappings:"]
    for rule in catalog.rules:
        tactic = dataset.tactics[rule.tactic_id]
        lines.append(f"  {rule.rule_id}  {rule.technique_id:<10} "
                     f"{dataset.display_name(rule.technique_id)}  [{rule.tactic_id} {tactic.name}]")
    lines += ["", "Reviewed but intentionally not mapped:"]
    for item in catalog.not_mapped:
        lines.append(f"  {item.technique_id:<10} {dataset.display_name(item.technique_id)}: "
                     f"{item.reason}")
    lines += ["", "Confidence scale:"]
    lines += [f"  {level:<7} {text}" for level, text in catalog.confidence_scale.items()]
    return ascii_safe("\n".join(lines))
