# Phase 9 — Persistence and Integration Seam

## Implemented

`security.storage` provides a framework-free SQLite service using only the Python standard library:

- `save_investigation(db_path, result)` stores a case and normalized child tables in one transaction.
- `get_investigation(db_path, case_id)` returns the saved JSON-compatible payload.
- `list_cases(db_path)` returns case summaries.
- `delete_case(db_path, case_id)` removes a case and dependent rows.
- Typed errors distinguish invalid input and missing cases.
- Parameterized SQL is used for values; case identifiers are validated.
- Foreign keys and composite keys keep finding-to-IOC and finding-to-mapping links within one case.
- Re-saving equivalent analysis content returns `unchanged`; a changed payload replaces the case atomically.
- The idempotency hash excludes analysis wall-clock fields (`generated_at`, each finding's `detected_at`) but preserves evidence timestamps and all other result content.

## Example

```python
from security.investigation import investigate_case
from security.storage import save_investigation, get_investigation

result = investigate_case("security/sample_evidence/INC-001")
status = save_investigation("data/sentinel.sqlite", result)
saved = get_investigation("data/sentinel.sqlite", result.incident_id)
```

## Authorization and deployment boundary

The optional `authorize(action, case_id)` callback is an enforcement hook for an integrating application. It is **not** an authentication system. If omitted, this local service does not authenticate callers; callers must enforce authorization at their trust boundary. No HTTP routes, user identity store, frontend, or production deployment configuration are included. The repository's requirements and existing README explicitly keep FastAPI/backend responsibilities in the separate backend project.

## SQLite schema

The database contains `cases`, `timeline_events`, `findings`, `iocs`, `mitre_mappings`, `finding_iocs`, and `finding_mappings`. Foreign keys are enabled for every connection. The database is created automatically when the first operation runs.

## Verification

Run:

```bash
python -m pytest -q
```

The Phase 9 tests cover create/read, idempotent save, replacement, case-ID validation, authorization-hook denial, missing-case behavior, and delete.
