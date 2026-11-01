# Phase 7 — MITRE ATT&CK Mapping

## Purpose and scope

Phase 7 maps findings produced by the existing detection engine (Phase 5) to a **curated subset** of MITRE ATT&CK Enterprise. It also carries through the evidence and IOC references that support each mapping. This is evidence-based mapping, not a claim that an observed event proves adversary intent.

The module is local and read-only: it makes no network requests and does not alter collector evidence. `map_case()` runs validation, normalization, timeline construction, detection, IOC extraction, and then ATT&CK mapping. `map_findings()` can map already-produced detection findings and optional matching IOC/timeline results.

## Quick start

From the repository root:

```bash
python -m security.mitre security/sample_evidence/INC-001
python -m security.mitre security/sample_evidence/INC-001 --json
python -m security.mitre security/sample_evidence/INC-001 --now 2026-10-19T00:00:00Z --json
python -m security.mitre --list
```

`--now` accepts an ISO-8601 timestamp with a timezone and makes time-dependent upstream detection reproducible. `--json` emits the structured `MitreResult`. `--list` reports supported mappings, intentionally omitted candidates, dataset metadata, and the confidence scale.

## Inputs and outputs

- Input: a collector evidence folder that conforms to `docs/EVIDENCE_CONTRACT.md`; optional detection and IOC configuration JSON files may be passed using `--config` and `--ioc-config`.
- Output: the case ID, ATT&CK dataset and mapping-definition metadata, aggregated mappings, findings copied with `mitre_techniques` populated, per-rule evaluations, and data gaps.
- A mapping identifies the most specific supported technique, the tactic supported by the evidence, related finding IDs, supporting event IDs, raw evidence record IDs, related IOC IDs, rationale, and confidence factors.
- Evaluations distinguish `mapped`, `not_mapped` (conditions evaluated and did not hold), `not_evaluable` (required information was unavailable), `no_rules`, and `duplicate`. Missing information is not silently treated as negative evidence.
- Mapping confidence is capped by the confidence of the supporting detection finding. When several findings support the same technique/tactic, the mapping is aggregated and reports the strongest source confidence with per-finding source details.

## Dataset and coverage limits

The bundled dataset is identified by the module's metadata as **MITRE ATT&CK Enterprise v19.2**, with a curated subset of techniques referenced by `security/mitre/mappings.json`, their parent techniques, and the associated tactics. It is not the full ATT&CK matrix. Mapping definitions are declarative and live in `security/mitre/mappings.json`; the bundled dataset lives in `security/mitre/attack_subset.json`.

Only techniques with defined rules and satisfied evidence conditions are emitted. `python -m security.mitre --list` also explains candidates that were reviewed but intentionally not mapped, such as cases where the evidence cannot establish adversary use, lateral movement, exposure, or a specific execution behavior.

## Exit codes

- `0`: the command completed; inspect the result to see whether any mappings were produced.
- `1`: evidence validation failed, so mapping did not run.
- `2`: invalid command-line/configuration input or invalid ATT&CK data/mapping definitions.

A zero exit code means the analysis ran, not that the evidence proves malicious activity or that every ATT&CK technique is covered.

## Verification

Run the complete test suite with:

```bash
python -m pytest -q
```

Phase 7's focused tests are in `tests/test_phase7_catalog.py`, `tests/test_phase7_conditions.py`, and `tests/test_phase7_mapper.py`. The mapper/CLI tests exercise the sample case, expected mappings, JSON output, mapping-list output, and missing-argument behavior.
