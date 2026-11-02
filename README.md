# Sentinel DFIR — Analysis & Investigation Module

Post-incident evidence analysis for the Sentinel DFIR platform.
Takes a folder of collector evidence (JSON) and produces structured, explainable findings.

```text
Evidence → Validation → Normalization → Timeline → Detection → IOCs → MITRE → Investigation
```

Scope: **analysis only.** The Windows Evidence Collector and preservation module are maintained separately and are not included in this repository. The expected evidence format is described in [`docs/EVIDENCE_CONTRACT.md`](docs/EVIDENCE_CONTRACT.md); compatibility with the separate collector has not been verified here.

## Quick start

```bash
pip install -r requirements.txt
python -m pytest -q                       # run all tests
python -m security.main                   # inventory of the sample case
python -m security.main --evidence <folder>   # inventory of any evidence folder
python -m security.validation <folder>    # validate an evidence folder (read-only)
python -m security.normalization <folder>  # validate + normalize into timeline events (read-only)
python -m security.timeline <folder>       # validate + normalize + print the incident timeline (read-only)
python -m security.detection <folder>      # validate + normalize + timeline + detection rules (read-only)
python -m security.ioc <folder>            # ... + IOC extraction from the evidence the findings cite (read-only)
python -m security.mitre <folder>          # ... + MITRE ATT&CK mapping (read-only)
python -m security.mitre <folder> --json   # structured mapping output
python -m security.mitre --list            # supported mappings, omissions, dataset, confidence scale
```

## Project structure

```text
sentinel-dfir-analysis/
├── docs/EVIDENCE_CONTRACT.md      Expected Collector → Analysis evidence contract
├── docs/NORMALIZATION.md          Normalization rules, event mapping, details keys
├── docs/TIMELINE.md               Timeline schema, summaries, filter semantics
├── docs/DETECTION.md              Rules, defaults, severity/confidence, IP policy, correlation
├── docs/IOC.md                    IOC scope, per-type rules, schema, limitations
├── docs/ATTACK_MAPPING.md         Curated ATT&CK mapping scope and limitations
├── docs/PHASE7_VERIFICATION.md    Phase 7 verification notes
├── docs/PHASE8_INVESTIGATION.md   Investigation assembly and interpretation limits
├── docs/PHASE9_STORAGE.md         Local SQLite persistence service
├── docs/PHASE8_9_COMPLETION_REPORT.md  Phase 8–9 implementation notes
├── examples/detection_synthetic_demo.json   EXPLICIT opt-in: documentation IPs count as external
├── scripts/                         Development scripts, including manifest and ATT&CK subset builders
├── tests/                         pytest coverage for contracts and analysis phases
└── security/
    ├── main.py                    Evidence inventory CLI
    ├── models/schemas.py          Contract constants + output dataclasses
    ├── utils/                      JSON loading, SHA-256, UTC timestamp parsing
    ├── validation/                Phase 2 - evidence validator
    │   ├── validator.py           validate_case(folder) -> ValidationResult (public API)
    │   ├── loader.py              safe read: empty / BOM / UTF-8 / JSON / duplicate keys
    │   ├── checks.py              envelope, field types, UTC timestamps, record IDs
    │   ├── manifest.py            manifest structure + SHA-256 verification
    │   ├── report.py              text report for the CLI
    │   └── __main__.py            python -m security.validation
    ├── normalization/             Phase 3 - evidence normalization
    │   ├── normalizer.py          normalize_case(folder) -> NormalizationResult (public API)
    │   ├── mappers.py             one raw record -> one NormalizedEvent, per source
    │   ├── enrichment.py          users.json -> user_context on events
    │   └── __main__.py            python -m security.normalization
    ├── timeline/                  Phase 4 - timeline reconstruction
    │   ├── timeline.py            build_case_timeline(folder) -> Timeline (public API)
    │   ├── filters.py             filter_timeline(...) by time / type / source / user / device
    │   ├── summaries.py           neutral one-line description per event
    │   ├── report.py              text rendering (ASCII only)
    │   └── __main__.py            python -m security.timeline
    ├── detection/                 Phase 5 - rule-based detection
    │   ├── engine.py              detect_case(folder) / run_detection(timeline) -> DetectionResult
    │   ├── rules.py               rule registry and order (DET-001 -> DET-002 -> DET-003)
    │   ├── brute_force.py         DET-001 possible brute-force logon attempts
    │   ├── powershell.py          DET-002 suspicious PowerShell activity
    │   ├── account_creation.py    DET-003 suspicious account creation
    │   ├── base.py                Rule base class, context, finding builder
    │   ├── config.py              validated, frozen configuration + JSON loading
    │   ├── ip_policy.py           IP classification and the "external" policy
    │   ├── report.py              ASCII text rendering
    │   └── __main__.py            python -m security.detection
    ├── ioc/                       Phase 6 - IOC extraction
    │   ├── extractor.py           extract_case_iocs(folder) / extract_iocs(timeline, detection) -> IocResult
    │   ├── parsers.py             validated IP / domain / URL / hash / path helpers (stdlib only)
    │   ├── config.py              validated, frozen configuration + JSON loading
    │   ├── report.py              ASCII text rendering
    │   └── __main__.py            python -m security.ioc
    ├── mitre/                     Phase 7 - curated MITRE ATT&CK mapping
    │   ├── mapper.py              Map findings to supported techniques
    │   ├── catalog.py             Curated technique catalog
    │   └── attack_subset.json     Local ATT&CK data subset
    ├── investigation/             Phase 8 - full case investigation assembly
    │   ├── investigator.py        investigate_case() -> InvestigationResult
    │   └── __main__.py            python -m security.investigation
    ├── storage/                   Phase 9 - local SQLite persistence service
    │   ├── store.py               save/read/list/delete investigation results
    │   └── __main__.py            python -m security.storage
    ├── ai/                        Initial AI contract boundary; no model integration
    │   ├── contract.py            AI input/output contract definitions
    │   ├── adapter.py             InvestigationResult payload adapter
    │   └── validation.py          Input/output structure and reference validation
    └── sample_evidence/INC-001/   Synthetic case (7 evidence files + manifest)
```

The collector is a separate project and is not represented in this tree. The sample evidence demonstrates the documented input shape; it does not verify compatibility with collector-produced evidence.

Repository layout notes:

| Area | Purpose |
|---|---|
| `security/validation/` | Implements the evidence validation stage. |
| `security/sample_evidence/INC-001/` | Synthetic case organized using the folder shape described by the evidence contract; this does not verify collector compatibility. |
| `docs/`, `scripts/`, and `tests/` | Keep project documentation, development utilities, and automated coverage at the repository root. |

## Phase status

| Phase | Deliverable | Status |
|---|---|---|
| 1 | Project structure, evidence contract, schemas, synthetic sample | Implemented |
| 2 | Read only evidence and manifest validation | Implemented |
| 3 | Evidence normalization and user context enrichment | Implemented |
| 4 | Timeline reconstruction, summaries, and filters | Implemented |
| 5 | Configurable rule based detection | Implemented |
| 6 | IOC extraction from cited evidence | Implemented |
| 7 | Curated MITRE ATT&CK mapping; see [docs/ATTACK_MAPPING.md](docs/ATTACK_MAPPING.md) | Implemented |
| 8 | Investigation assembly, provenance reference checks, and analyst review suggestions | Implemented |
| 9 | Local SQLite persistence service | Implemented |
| 10 | Integration tests, including five required test cases | Planned |

## Validation (Phase 2)

```bash
python -m security.validation security/sample_evidence/INC-001          # text report
python -m security.validation security/sample_evidence/INC-001 --json   # for the backend
```

Exit code `0` = valid (warnings allowed), `1` = invalid. From Python:

```python
from security.validation import validate_case

result = validate_case("security/sample_evidence/INC-001")
result.valid          # True only when there are no errors
result.errors         # list[ValidationIssue]  -> evidence must NOT be analyzed
result.warnings       # list[ValidationIssue]  -> usable, but worth reading
result.checked_files  # files that were found and examined
result.case_id, result.device
result.to_dict()      # JSON-safe, ready for FastAPI / SQL
```

Each `ValidationIssue` has `code`, `severity`, `message`, `file`, `record_id`, `field`. The message always names the file, record and field, e.g.
`processes.json PROC-0001: field 'pid' must be an integer, got str 'abc'.`

The validator is **read-only**: it never edits evidence, never creates a missing manifest and never "repairs" a failed one. It reports every problem it finds instead of stopping at the first.

| Check | Error codes | Warning codes |
|---|---|---|
| Folder / required files | `CASE_DIR_NOT_FOUND`, `REQUIRED_FILE_MISSING`, `FILE_UNREADABLE` | `OPTIONAL_FILE_MISSING` (`files.json`) |
| JSON integrity | `FILE_EMPTY`, `JSON_INVALID`, `JSON_BOM`, `FILE_NOT_UTF8`, `JSON_DUPLICATE_KEY`, `JSON_NOT_OBJECT` | |
| Envelope | `ENVELOPE_FIELD_MISSING`, `SOURCE_MISMATCH`, `SCHEMA_VERSION_INVALID`, `SCHEMA_VERSION_UNSUPPORTED` | `SCHEMA_MINOR_NEWER` |
| Records | `RECORDS_NOT_LIST`, `RECORD_NOT_OBJECT`, `SYSTEM_RECORD_COUNT`, `FIELD_MISSING`, `FIELD_NULL`, `FIELD_EMPTY`, `FIELD_TYPE`, `FIELD_VALUE` | `RECORDS_EMPTY`, `FIELD_EMPTY` (optional fields) |
| Timestamps | `TIMESTAMP_INVALID` (must be UTC ending in `Z`) | |
| Record IDs | `RECORD_ID_MISSING`, `RECORD_ID_FORMAT`, `RECORD_ID_DUPLICATE` | |
| Case consistency | `CASE_ID_MISMATCH`, `DEVICE_MISMATCH` | `HOSTNAME_DEVICE_MISMATCH` |
| Manifest | `MANIFEST_MISSING`, `MANIFEST_FIELD_MISSING`, `MANIFEST_HASH_ALGORITHM`, `MANIFEST_FILES_NOT_LIST`, `MANIFEST_ENTRY_INVALID`, `MANIFEST_DUPLICATE_ENTRY`, `MANIFEST_BAD_FILE_NAME`, `MANIFEST_HASH_MISMATCH`, `MANIFEST_SIZE_MISMATCH`, `MANIFEST_RECORD_COUNT`, `MANIFEST_FILE_UNLISTED`, `MANIFEST_FILE_MISSING` | `MANIFEST_UNKNOWN_FILE` |

Null policy: a required field may not be `null`, with one documented exception: `processes.command_line` must be present in every record but may be `null` when the collector cannot retrieve it (`NULLABLE_REQUIRED_FIELDS` in `schemas.py`; contract section 2).

Not validated (semantic rules the collector owns): that times were really converted to UTC, that PowerShell commands are decoded rather than Base64, and that secrets were redacted.

## Normalization (Phase 3)

```bash
python -m security.normalization security/sample_evidence/INC-001                # summary + first 10 events
python -m security.normalization security/sample_evidence/INC-001 --limit 0      # every event
python -m security.normalization security/sample_evidence/INC-001 --json         # full result for the backend
```

```python
from security.normalization import normalize_case
from security.validation import EvidenceNotValidError

try:
    result = normalize_case("security/sample_evidence/INC-001")
except EvidenceNotValidError as error:
    print(error.result.errors)          # invalid evidence is never normalized

result.events      # list[NormalizedEvent], chronological, ids E-00001...
result.host        # system.json record (host context, not an event)
result.users       # users.json records (enrichment source, not events)
result.warnings    # data-quality notes (a value was null / malformed)
result.validation  # the ValidationResult the events came from
```

Sample case: 32 events from 32 records (12 Windows events, 9 processes, 5 connections, 3 PowerShell, 3 files). `users.json` and `system.json` produce **no** events.
Full rules, the per-type `details` keys and warning codes are in [`docs/NORMALIZATION.md`](docs/NORMALIZATION.md).

Not in Phase 3 (by design): chronological timeline views (Phase 4), "is this IP external?" and other detection policy (Phase 5), IOC extraction, MITRE mapping.

## Timeline (Phase 4)

```bash
python -m security.timeline security/sample_evidence/INC-001                       # full timeline
python -m security.timeline security/sample_evidence/INC-001 --limit 10            # first 10 rows
python -m security.timeline security/sample_evidence/INC-001 --json                # for the backend / frontend

# filters (AND between flags, repeat a flag for OR)
python -m security.timeline security/sample_evidence/INC-001 \
    --type logon_failed --user ahmed --start 2026-10-08T07:31:00Z --end 2026-10-08T07:33:00Z
python -m security.timeline security/sample_evidence/INC-001 --source network --device WIN-PC-01
```

Exit codes: `0` ok (an empty selection is not an error), `1` evidence failed validation, `2` invalid filter.

```python
from security.timeline import build_case_timeline, filter_timeline, format_timeline

timeline = build_case_timeline("security/sample_evidence/INC-001")   # validates + normalizes first
for entry in timeline.entries:
    print(entry.sequence, entry.event_id, entry.timestamp, entry.gap_from_previous_seconds, entry.summary)

rdp_failures = filter_timeline(timeline, event_types="logon_failed", users="ahmed")
timeline.get_by_evidence_id("PROC-0006")      # trace an entry back to its raw record
entry.to_event()                              # the exact NormalizedEvent it came from
print(format_timeline(rdp_failures))
```

Excerpt of the sample timeline (`gap` = time since the previous event):

```text
seq  event    timestamp (UTC)            gap  type                 evidence    user          summary
 11  E-00011  2026-10-08T07:31:02Z       +2s  logon_failed         EVL-0004    ahmed         Failed logon (RemoteInteractive) for ahmed from 198.51.100.23: wrong password
 18  E-00018  2026-10-08T07:32:40Z       +2s  logon_success        EVL-0010    ahmed         Successful logon (RemoteInteractive) for ahmed from 198.51.100.23
 22  E-00022  2026-10-08T07:34:01Z       +9s  process_created      PROC-0006   ahmed         Process created: powershell.exe (PID 6012) by ahmed, parent wscript.exe
 25  E-00025  2026-10-08T07:34:12Z       +3s  network_connection   NET-0004    -             Outbound TCP 10.20.0.15:49822 -> 203.0.113.77:443 (powershell.exe, files-sync.example.net)
 30  E-00030  2026-10-08T07:35:22Z       +2s  account_created      EVL-0011    ahmed         Account 'svc_helpdesk' created by ahmed
```

Identical timestamps are ordered by source (events, processes, network, powershell, files), then by numeric record number, so the result never depends on input order. A filtered timeline keeps `event_id` / `evidence_id` and renumbers `sequence`, gaps and offsets. Full schema, summary templates and filter semantics: [`docs/TIMELINE.md`](docs/TIMELINE.md).

Not in Phase 4 (by design): detection rules, IOC extraction, MITRE mapping, investigation logic. Summaries state facts only and never call anything suspicious.

## Detection (Phase 5)

```bash
python -m security.detection security/sample_evidence/INC-001                          # text report
python -m security.detection security/sample_evidence/INC-001 --json --now 2026-10-09T12:00:00Z
python -m security.detection security/sample_evidence/INC-001 --rule DET-001 --rule DET-002
python -m security.detection security/sample_evidence/INC-001 --config my_config.json
python -m security.detection security/sample_evidence/INC-001 --config examples/detection_synthetic_demo.json   # explicit synthetic-demo opt-in
```

Exit codes: `0` ran (findings are results, not errors), `1` evidence failed validation, `2` invalid option or configuration.

```python
from security.detection import detect_case, format_detection, DetectionConfig

config = DetectionConfig.from_dict({"brute_force": {"threshold": 3, "window_seconds": 60}})
result = detect_case("security/sample_evidence/INC-001", config=config)   # validates + normalizes first
for finding in result.findings:
    print(finding.finding_id, finding.rule_id, finding.severity.value, finding.supporting_events)
for rule in result.rules:
    print(rule.rule_id, rule.events_considered, rule.findings, rule.data_gaps)   # gaps != negative
```

| Rule | Detects | Key defaults |
|---|---|---|
| DET-001 | >= `threshold` failed logons for one **(device, account, source IP)** within `window_seconds`; notes a following successful logon from the same source | 5 failures, 120 s, success window 300 s |
| DET-002 | one PowerShell process (device + PID) with >= `min_indicators` of 8 explicit indicators (encoded command, hidden window, policy bypass, download function, invoke-expression, unusual parent, user-writable script path, external connection) | 2 indicators, 900 s correlation window |
| DET-003 | account creation whose **target** is privileged and whose **actor** has linked context (process chain from a DET-002 finding, or an earlier brute-force finding) | privileged target + 1 context indicator |

Findings carry severity (capped at High), confidence (how well the conditions are met and linked, **not** the chance of malicious intent), `matched_indicators`, supporting event ids, raw record ids and files. Public IPs are never assumed malicious; "external" is a configurable policy: **only genuinely public addresses by default**; documentation ranges are classified separately and are never external unless you opt in explicitly. Rules link records only through PID / device / user / bounded time windows, never by time alone. Everything (grouping and counting rules, indicators, IP table, correlation conditions, limitations) is in [`docs/DETECTION.md`](docs/DETECTION.md).

Sample case result under the default policy (excerpt of the real output; the single failed logon at 06:54, the scheduled `disk-report.ps1`, Chrome traffic and the inbound RDP connections are correctly **not** flagged):

```text
Case ID  : INC-001
Events   : 32
Findings : 4

Rules:
  DET-001  Possible Brute-Force Logon Attempts: examined 7 event(s), 1 finding(s), 1 data gap(s)
  DET-002  Suspicious PowerShell Activity: examined 8 event(s), 2 finding(s), 0 data gap(s)
  DET-003  Suspicious Account Creation: examined 1 event(s), 1 finding(s), 0 data gap(s)

F-001  Possible Brute-Force Logon Attempts  [DET-001]
  Severity   : High    Confidence: Medium
  When       : 2026-10-08T07:31:02Z -> 2026-10-08T07:32:40Z (1m38s)
...

F-004  Suspicious Account Creation  [DET-003]
  Severity   : High    Confidence: High
  When       : 2026-10-08T07:32:40Z -> 2026-10-08T07:35:31Z (2m51s)
  Device/User: WIN-PC-01 / ahmed
  Reason     : Account creation by 'ahmed' of 'svc_helpdesk': privileged target = yes; 2 context indicator(s) matched (minimum 1): process_chain_linked_to_powershell_finding, actor_account_targeted_by_bruteforce.
  Details    : Account 'svc_helpdesk' was created on WIN-PC-01 at 2026-10-08T07:35:22Z by 'ahmed'. Privileged target: yes. Context indicators matched: process_chain_linked_to_powershell_finding, actor_account_targeted_by_bruteforce.
  Indicators :
    privileged_target: EVL-0012, USR-0006
    process_chain_linked_to_powershell_finding: F-002, F-003
    actor_account_targeted_by_bruteforce: F-001
```

Not in Phase 5 (by design): IOC extraction, MITRE ATT&CK mapping, recommended next steps, investigation reports, backend/database integration. Those fields exist on `Finding` but stay empty.

## IOC extraction (Phase 6)

```bash
python -m security.ioc security/sample_evidence/INC-001                     # text report
python -m security.ioc security/sample_evidence/INC-001 --json --now 2026-10-09T12:00:00Z
python -m security.ioc security/sample_evidence/INC-001 --ioc-config my_ioc.json
python -m security.ioc security/sample_evidence/INC-001 --config my_detection.json
```

Exit codes: `0` ran, `1` evidence failed validation, `2` invalid option or configuration.

```python
from security.ioc import extract_case_iocs, IocConfig

result = extract_case_iocs("security/sample_evidence/INC-001")           # validates -> ... -> detects -> extracts
for ioc in result.iocs:
    print(ioc.ioc_id, ioc.type.value, ioc.value, ioc.related_findings, len(ioc.occurrences))
for finding in result.findings:                                          # copies of the findings with .iocs filled in
    print(finding.finding_id, finding.iocs)
print(result.data_gaps)                                                  # invalid values that were NOT extracted
```

Only evidence that a finding **cites** is examined (its supporting events plus the records it lists as correlated), so benign traffic never becomes an IOC. Every value is validated (IPs with `ipaddress`, URLs with `urllib`, domains and hashes by explicit rules), one IOC exists per unique value with **every occurrence** kept (record, file, field, time, role) and the findings it relates to, and file records are linked only by **exact path**. IOCs are observables found in suspicious activity, not verdicts. Full rules, schema, defaults and limitations: [`docs/IOC.md`](docs/IOC.md).

Sample case (excerpt of the real output):

```text
Case ID : INC-001
IOCs    : 10 (domain=1, filename=2, hash=2, ip=2, url=1, username=2)

IOC-001  ip        198.51.100.23
    class=documentation, external by policy=no
    findings: F-001, F-004   occurrences: 7
    first: events.json EVL-0004 (source_ip): source address of a failed logon (RemoteInteractive) (+6 more occurrence(s))

IOC-006  url       https://files-sync.example.net/stage/update_svc.ps1
    host=files-sync.example.net (domain)
    findings: F-002, F-004   occurrences: 3
    first: processes.json PROC-0006 (command_line (decoded)): URL found in command_line (decoded) (+2 more occurrence(s))

IOC-008  hash      dc2b08f6eff0cd3255c996ab6f9ff4f922504bc447eb252cfb03c9e451649a84
    sha256 of C:\Users\Public\update_svc.ps1
    findings: F-002, F-003, F-004   occurrences: 1
    first: files.json FILE-0003 (sha256): hash of the file update_svc.ps1

...

Findings -> IOCs:
  F-001: IOC-001, IOC-002
  F-002: IOC-002, IOC-005, IOC-006, IOC-007, IOC-008, IOC-009
  F-003: IOC-002, IOC-005, IOC-007, IOC-008, IOC-009
  F-004: IOC-001, IOC-002, IOC-003, IOC-004, IOC-005, IOC-006, IOC-007, IOC-008, IOC-010
```

Not in Phase 6 (by design): MITRE ATT&CK mapping, investigation reports, threat-intelligence enrichment, backend/database integration.

## Sample case INC-001 — ground truth

All data is synthetic. IPs use reserved documentation ranges (`198.51.100.0/24`, `203.0.113.0/24`, `192.0.2.0/24`), domains use `example.net/.org`, hashes are fake, and the PowerShell is a non-functional placeholder. Times are UTC, 2026-10-08, device `WIN-PC-01`. Under the default IP policy these documentation addresses are not "external" (see Detection).

| Time | What happens | Should the engine flag it? |
|---|---|---|
| 06:54:58 | Single failed logon (`ahmed`, local) | **No** — one typo is not brute force |
| 06:55:12 | Normal interactive logon | No |
| 07:02:44 | Chrome → `192.0.2.44:443` | No — normal external traffic |
| 07:15:03 | Scheduled `disk-report.ps1` as `svc_backup` | **No** — benign PowerShell (false-positive control) |
| 07:31:02–07:32:08 | 6 failed RDP logons for `ahmed` from `198.51.100.23` | **Yes** — possible brute force |
| 07:32:40 | Successful RDP logon, same IP | Yes — raises severity of the brute-force finding |
| 07:33:52 | `wscript.exe` runs `invoice_update.vbs` | Context |
| 07:34:01 | `wscript.exe` → `powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -EncodedCommand …` | **Yes** — suspicious PowerShell |
| 07:34:12 | PowerShell -> `203.0.113.77:443` (`files-sync.example.net`) | Correlated to the PowerShell process (same PID); it counts as an *external connection* only under the explicit synthetic-demo policy, because documentation ranges are not external by default |
| 07:35:22 | Account `svc_helpdesk` created by `ahmed` | **Yes** — suspicious account creation |
| 07:35:31 | `svc_helpdesk` added to Administrators | Yes — privileged account |

Findings produced by Phase 5 on this case: **F-001** brute-force burst followed by a successful logon (DET-001), **F-002** and **F-003** the two PowerShell processes (DET-002), **F-004** the privileged account created by that chain (DET-003). IOCs extracted from that evidence in Phase 6: 2 IPs (`198.51.100.23`, `203.0.113.77`), the domain `files-sync.example.net`, its URL, the files `update_svc.ps1` and `invoice_update.vbs` with their SHA-256 hashes (linked by exact path), and the accounts `ahmed` and `svc_helpdesk`. Phase 7 maps the supported findings to the curated ATT&CK subset; run `python -m security.mitre security/sample_evidence/INC-001` to inspect the result. See [`docs/ATTACK_MAPPING.md`](docs/ATTACK_MAPPING.md) for scope and limitations.

## MVP vs future

| Required for MVP | Optional future enhancement |
|---|---|
| Custom deterministic rules (3 scenarios) | **Sigma** — load standard YAML rules into `detection/` after the custom engine works |
| Regex + `ipaddress` IOC extraction | **STIX/TAXII** — export `IOC` objects as STIX indicators / enrich against a TAXII feed; `IOC` already has `type`+`value`+context |
| Hand-written ATT&CK table for supported techniques | **YARA** — only if the collector delivers file contents; `files.json` today holds metadata/hashes only |
| Local SQLite persistence service for investigation results | A separate application backend/API, authentication, and web interface |


## Phase 8: Investigation Engine

The investigation engine assembles validation, normalization, timeline, detection, IOC extraction, and ATT&CK mapping into a traceable `InvestigationResult`:

```bash
python -m security.investigation security/sample_evidence/INC-001 --output investigation.json
```

For an optional local AI demonstration, select the mock provider explicitly:

```bash
python -m security.investigation security/sample_evidence/INC-001 --ai-provider mock
```

The deterministic investigation JSON keeps its existing format on stdout (or
in the `--output` file). The separate AI report is written to stderr and is
labeled `MOCK/DEMO — NOT REAL LLM ANALYSIS`.

See [`docs/PHASE8_INVESTIGATION.md`](docs/PHASE8_INVESTIGATION.md).

## Phase 9: SQLite persistence

Persist a newly analyzed case to a local SQLite database:

```bash
python -m security.storage security/sample_evidence/INC-001 --database data/sentinel.sqlite
```

The storage service is an integration seam only; this repository does not implement HTTP routes, authentication, a web interface, or the separate backend project. See [`docs/PHASE9_STORAGE.md`](docs/PHASE9_STORAGE.md).

## AI module status

`security.ai` provides a privacy-filtered, reference-validated boundary around
deterministic investigation results. Its synchronous service currently supports
the local deterministic Mock Provider only. The mock selects application-built
confirmed facts and returns no model-authored observations, hypotheses, or
recommendations.

Use `--ai-provider mock` to print the separate report on stderr. Its heading is
`MOCK/DEMO — NOT REAL LLM ANALYSIS`. Existing deterministic JSON output is unchanged.
There is no real LLM integration, network access, API-key handling, AI-result
database persistence, or frontend integration. AI results do not change the
authoritative `InvestigationResult`.
