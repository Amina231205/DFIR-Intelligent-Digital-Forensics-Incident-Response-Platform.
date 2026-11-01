# Sentinel DFIR — Normalization (Phase 3)

`normalize_case(folder)` turns a **validated** evidence folder into one list of `NormalizedEvent` objects plus host/user context.

```text
validate_and_load ──► (invalid) raise EvidenceNotValidError
        │
        ▼ same bytes that passed the SHA-256 check
 mappers (1 record → 1 event) ─► user enrichment ─► deterministic order + E-00001… ids
```

## Guarantees

| Guarantee | How |
|---|---|
| Validated input only | `normalize_case` calls `validate_and_load`; any error raises `EvidenceNotValidError` (full `ValidationResult` on `.result`). No partial output. |
| Analyzed bytes = validated bytes | Files are read once; the parsed data from the validation pass is reused. |
| Read-only | Nothing is written; input dicts are never mutated; output holds copies. |
| Deterministic | Order key = `(timestamp, source rank, record number, record_id)`; independent of record order inside files. |
| Traceable | `evidence_id` = source `record_id`. One record → exactly one event; nothing dropped. |
| Stable shape | Each event type has a fixed set of `details` keys; missing values are `null`. |

## What becomes an event

| File | Event? | Event type(s) | `user` is… |
|---|---|---|---|
| events.json | yes | `logon_success` (4624), `logon_failed` (4625), `account_created` (4720), `group_member_added` (4732), else `other` | logon: the account logging on · 4720/4732: the **actor** (`SubjectUserName`) |
| processes.json | yes | `process_created` | `user` |
| network.json | yes | `network_connection` | `user` if the collector gave one, else `null` |
| powershell.json | yes | `powershell_executed` | `user` |
| files.json (optional) | yes | `file_created` (time = creation time) | `owner` or `null` |
| users.json | **no** | enrichment only → `details.user_context` / `target_user_context` | — |
| system.json | **no** | host context → `NormalizationResult.host` | — |

Event IDs are numbered `E-00001…` in the deterministic order above. Same-timestamp ties are ordered events → processes → network → powershell → files, then by numeric record number.

## `details` keys per event type

Every event also gets `user_context` (dict or `null`).

| Type | Keys |
|---|---|
| `logon_success` | `windows_event_id, channel, provider, record_number, logon_type, logon_type_name, source_ip, workstation, target_domain, logon_process, authentication_package` |
| `logon_failed` | the logon keys + `status, sub_status, failure_reason` |
| `account_created` | `windows_event_id, channel, provider, record_number, target_user, target_domain, target_sid, sam_account_name, subject_domain` + `target_user_context` |
| `group_member_added` | `windows_event_id, channel, provider, record_number, group, group_domain, member, member_name, member_sid, subject_domain` + `target_user_context` |
| `other` | `windows_event_id, channel, provider, record_number, data` (raw EventData copy) |
| `process_created` | `pid, ppid, name, parent_name, command_line (may be null), executable_path, sha256, origin` |
| `network_connection` | `protocol, direction, local_address, local_port, remote_address, remote_port, state, pid, process_name, remote_hostname, origin` |
| `powershell_executed` | `pid, command, script_path, host_application, windows_event_id, log, origin` |
| `file_created` | `path, name, size_bytes, sha256, modified_at, owner` |

`user_context` = `{evidence_id, username, account_type, enabled, is_admin, groups, created_at}` from users.json (case-insensitive match; `evidence_id` is the `USR-…` record).

## Normalization rules worth knowing

- Windows `"-"` and blank `EventData` values become `null` (the contract keeps raw `EventData` verbatim; cleaning is normalization's job).
- A supported event ID only counts in the **Security** channel; the same ID elsewhere is `other`.
- Unsupported Windows events are **kept** as `other` with their raw `data`, not dropped (the contract allowed either; keeping loses no evidence, and filtering is a later-stage choice).
- Missing or malformed `EventData` fields never stop normalization: the value is `null` and a `NormalizationWarning` is recorded.
- No "is this IP external?" flag is derived here. Python's `ipaddress` treats the documentation ranges used in the samples as private, and what counts as internal is a detection policy decision (Phase 5).
- Duplicate usernames in users.json: first record wins, warning `USERS_DUPLICATE_USERNAME`.

## Warning codes

| Code | Meaning |
|---|---|
| `EVENT_DATA_MISSING_FIELD` | An expected Windows `EventData` field is absent or `-` |
| `EVENT_DATA_INVALID` | A field is present but unusable (e.g. non-numeric `LogonType`) |
| `USERS_DUPLICATE_USERNAME` | Two users.json records share a username (case-insensitive) |
