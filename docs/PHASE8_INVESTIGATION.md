# Phase 8 — Investigation Engine

## Purpose

`security.investigation.investigate_case()` assembles the existing public analysis stages into one case-level `InvestigationResult`. It does not replace the existing rules or assert that an alert proves compromise.

## Workflow

1. `validate_and_load()` validates the evidence and reads/hash-checks each evidence JSON file once.
2. `normalize_validated()` consumes the parsed, validated objects without reopening evidence files.
3. The normalized events are converted to a timeline.
4. Existing detection, IOC extraction, and ATT&CK mapping functions run against that timeline.
5. The investigation result is assembled with findings, evidence references, IOCs, supported mappings, timeline bounds, and evidence-file hashes/sizes.
6. A provenance consistency check verifies that finding event/record/IOC references resolve to items in the assembled case.
7. Findings receive conservative, rule-specific analyst next steps. Observations and interpretation are stored separately in `finding_assessments`.

## API

```python
from security.investigation import investigate_case, investigation_to_json

result = investigate_case("security/sample_evidence/INC-001")
print(investigation_to_json(result))
```

Pass a timezone-aware `now` to make test output deterministic:

```python
from datetime import datetime, timezone
result = investigate_case(
    "security/sample_evidence/INC-001",
    now=datetime(2026, 1, 1, tzinfo=timezone.utc),
)
```

Invalid evidence raises `EvidenceNotValidError`; it is not silently analyzed.

## Interpretation limits

- Rule matches are triage signals, not proof of compromise.
- The provenance check verifies reference consistency, not authenticity, chain of custody beyond the existing manifest check, or legal admissibility.
- Duplicate-looking observations and timestamps later than a source envelope's `collected_at` are flagged as data gaps; the engine does not delete or correct them.
- Next steps are deterministic review suggestions derived from the rule family and severity, not autonomous containment instructions.
- AI is not required and is not part of this phase.
