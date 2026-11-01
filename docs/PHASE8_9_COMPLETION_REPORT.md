# Phase 8–9 Completion Report

## Implemented in this working copy

### Phase 8 — Investigation engine
- `security/investigation/investigator.py`: `investigate_case()` orchestrates validation, normalization, timeline construction, detection, IOC extraction, and supported ATT&CK mapping.
- Uses evidence objects parsed by the validator instead of reopening evidence files during the analysis pipeline.
- Adds a case summary, evidence file SHA-256/size metadata, finding assessments separating observed facts from interpretation, finding links, data-gap reporting, and a provenance-reference consistency check.
- Adds deterministic, conservative analyst next steps; these are review suggestions, not automatic response actions.
- Adds JSON serialization and a CLI: `python -m security.investigation <evidence_dir> --output investigation.json`.
- `InvestigationResult` additions are optional to preserve the existing schema's backwards compatibility.

### Phase 9 — Persistence and integration seam
- `security/storage/store.py`: standard-library SQLite storage with transactional writes, parameterized SQL, validated case IDs, foreign keys, case-scoped composite keys for finding-to-IOC and finding-to-mapping relationships, read/list/delete APIs, and typed storage errors.
- Idempotency fingerprint ignores analysis wall-clock fields (`generated_at` and finding `detected_at`) while retaining evidence timestamps and other result data.
- Optional authorization callback is an integration hook only; it is not an authentication implementation.
- Adds a CLI: `python -m security.storage <evidence_dir> --database data/sentinel.sqlite`.
- No HTTP routes, web interface, user authentication, or separate FastAPI backend were added because the uploaded repository explicitly keeps those in the separate backend project.

## Verification performed
- Full existing and new pytest suite: **1633 passed**.
- Python bytecode compilation: passed.
- Investigation CLI on `security/sample_evidence/INC-001`: passed; produced structured JSON.
- Manual storage smoke test: first save returned `created`, repeat save returned `unchanged`, and the saved case was readable.
- `pyflakes` and `pycodestyle` could not be run because those packages are not installed in the environment. They are not claimed as passing.

## Important limitations
- Tests use the repository's synthetic sample evidence. They do not establish real-world detection accuracy.
- Provenance checking verifies internal reference consistency, not the authenticity or legal admissibility of evidence.
- SQLite is local persistence, not a replacement for the separately maintained API/backend, web UI, or production authentication.
