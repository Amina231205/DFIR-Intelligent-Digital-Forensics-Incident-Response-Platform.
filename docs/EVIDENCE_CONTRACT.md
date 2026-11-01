# Sentinel DFIR — Evidence JSON Contract (v1.0)

**Producer:** Windows Evidence Collection & Preservation module
**Consumer:** DFIR Analysis & Investigation module
**Rule:** the analysis engine only reads what is written here. If the collector follows this document, the sample evidence can be swapped for real evidence with **no code changes** in the analysis engine.

Machine-readable version of this contract: `security/models/schemas.py`
(`REQUIRED_SOURCES`, `ENVELOPE_FIELDS`, `REQUIRED_RECORD_FIELDS`, `RECORD_ID_PREFIX`).

---

## 1. Folder layout

One folder = one device = one collection run.

```text
<case_folder>/            e.g. INC-001/
├── manifest.json         REQUIRED  integrity + inventory (SHA-256 per file)
├── system.json           REQUIRED  host metadata (context only, no timeline events)
├── processes.json        REQUIRED
├── network.json          REQUIRED
├── users.json            REQUIRED  account snapshot (enrichment, no timeline events)
├── events.json           REQUIRED  Windows Event Log records
├── powershell.json       REQUIRED
└── files.json            OPTIONAL  files of interest (validator warns if missing)
```

Multi-device cases (future): one folder per device, same `case_id`.

## 2. Global rules

| Rule | Detail |
|---|---|
| Encoding | UTF-8 JSON, one object per file |
| Timestamps | ISO 8601 **UTC with `Z`**: `2026-10-08T07:34:01Z`. No local time, no naive timestamps. The collector converts Windows local time to UTC. |
| Missing values | Use `null`, never `""`, `"N/A"`, or `"-"` (exception: raw Windows `EventData` values inside `events.data` are kept verbatim). **Required fields may not be `null`, with one exception:** `processes.command_line` must be present in every record but may be `null` when the collector genuinely cannot retrieve it (e.g. protected system processes). An empty string is still invalid there. |
| IDs | Every record has a unique `record_id` = `<PREFIX>-<4+ digits>`; prefixes: `SYS`, `PROC`, `NET`, `USR`, `EVL`, `PS`, `FILE`. Findings cite these IDs. |
| Extra fields | Allowed and ignored by the analysis engine (forward compatible) |
| Secrets | Never store passwords/tokens. Replace with `[REDACTED]`. |
| Versioning | `schema_version` is `MAJOR.MINOR`. Minor = additive only. Major = breaking, must be agreed with the analysis owner first. |
| Consistency | `case_id` and `device` must be identical in every file and in the manifest |

## 3. Envelope (every evidence file)

```json
{
  "schema_version": "1.0",
  "case_id": "INC-001",
  "device": "WIN-PC-01",
  "source": "processes",
  "collected_at": "2026-10-08T08:10:00Z",
  "collector": { "name": "sentinel-windows-collector", "version": "0.1.0" },
  "records": [ ]
}
```

`source` must equal the file name without `.json`. `records` is always a list (`system.json` has exactly one record).

## 4. Record fields per source

`R` = required, `O` = optional (may be absent or `null`).

### system.json — host context (1 record)
| Field | Type | | Notes |
|---|---|---|---|
| record_id | str | R | `SYS-0001` |
| hostname | str | R | |
| os_name / os_version / architecture | str | R | e.g. `Windows 10 Pro` / `10.0.19045` / `AMD64` |
| boot_time | ts | R | |
| domain, timezone, utc_offset_minutes, ip_addresses | str/int/list | O | |

### processes.json — process creation records
| Field | Type | | Notes |
|---|---|---|---|
| record_id | str | R | `PROC-0001` |
| timestamp | ts | R | **process start time** |
| pid, ppid | int | R | |
| name | str | R | `powershell.exe` |
| command_line | str or `null` | R | full command line (redact secrets). **Key required; value may be `null`** when the collector cannot retrieve it. Never `""`. |
| user | str | R | account name without domain prefix |
| parent_name | str | O | needed for "unusual parent" detection |
| executable_path, sha256 | str | O | |
| origin | str | O | `event_log` (e.g. 4688/Sysmon history) or `live_snapshot` (running process at collection) |

### network.json — connections
| Field | Type | | Notes |
|---|---|---|---|
| record_id | str | R | `NET-0001` |
| timestamp | ts | R | time connection was seen (snapshot: collection time) |
| protocol | str | R | `TCP` / `UDP` |
| local_address, remote_address | str | R | IPv4 string |
| local_port, remote_port | int | R | |
| direction | str | R | `inbound` / `outbound` |
| pid, process_name | int/str | R | |
| state, remote_hostname, user, origin | str | O | `origin`: `event_log` or `live_snapshot` |

### users.json — local account snapshot (state, not events)
| Field | Type | | Notes |
|---|---|---|---|
| record_id | str | R | `USR-0001` |
| username | str | R | |
| account_type | str | R | `local` / `domain` |
| enabled, is_admin | bool | R | `is_admin` = member of Administrators |
| created_at | ts | R | used to cross-check Event 4720 |
| sid, groups, last_logon | str/list/ts | O | |

### events.json — Windows Event Log records
| Field | Type | | Notes |
|---|---|---|---|
| record_id | str | R | `EVL-0001` |
| timestamp | ts | R | `TimeCreated` in UTC |
| event_id | int | R | Windows event ID |
| channel, provider | str | R | `Security`, `Microsoft-Windows-Security-Auditing` |
| data | object | R | **raw `EventData` as key/value pairs, Windows field names unchanged** (`TargetUserName`, `IpAddress`, `LogonType` …) |
| record_number, keywords | int/str | O | `EventRecordID`, `Audit Success/Failure` |

MVP event IDs used by the analysis engine:

| Event ID | Meaning | Normalized `event_type` |
|---|---|---|
| 4624 | Successful logon | `logon_success` |
| 4625 | Failed logon | `logon_failed` |
| 4720 | User account created | `account_created` |
| 4732 | Member added to a security-enabled local group | `group_member_added` |

Other IDs may be present; they are kept as `other` or ignored.

### powershell.json — PowerShell activity
| Field | Type | | Notes |
|---|---|---|---|
| record_id | str | R | `PS-0001` |
| timestamp | ts | R | |
| user | str | R | |
| pid | int | R | links to `processes.json` |
| command | str | R | script block text (Event 4104) — **decoded**, not Base64 |
| event_id, log, origin | int/str | O | `origin`: `script_block_log` or `psreadline_history` |
| script_path | str/null | O | |
| host_application | str | O | the full command line that launched the engine |

### files.json — files of interest (optional)
| Field | Type | | Notes |
|---|---|---|---|
| record_id | str | R | `FILE-0001` |
| timestamp | ts | R | **creation time** |
| path, name | str | R | |
| size_bytes | int | R | |
| sha256 | str | R | lowercase hex |
| modified_at, owner | ts/str | O | |

The collector decides *which* files are of interest (e.g. recently created in user-writable folders). The analysis module never scans disks.

## 5. manifest.json (chain of custody)

```json
{
  "schema_version": "1.0",
  "case_id": "INC-001",
  "device": "WIN-PC-01",
  "hash_algorithm": "SHA-256",
  "created_at": "2026-10-08T08:10:00Z",
  "collector": { "name": "...", "version": "..." },
  "files": [
    { "name": "processes.json", "sha256": "…", "size_bytes": 4812, "record_count": 9 }
  ]
}
```

The Phase 2 validator recomputes each hash. A mismatch is a **hard error** (evidence changed after collection).

## 6. Output: normalized event (analysis-internal, stored as `TimelineEvents`)

```json
{
  "event_id": "E-00014",
  "case_id": "INC-001",
  "timestamp": "2026-10-08T07:34:01Z",
  "event_type": "process_created",
  "source": "processes",
  "device": "WIN-PC-01",
  "user": "ahmed",
  "evidence_id": "PROC-0006",
  "details": { "pid": 6012, "ppid": 5120, "name": "powershell.exe", "parent_name": "wscript.exe" }
}
```

Event types: `logon_success`, `logon_failed`, `process_created`, `network_connection`, `powershell_executed`, `account_created`, `group_member_added`, `file_created`, `other`.

| Source | Becomes events? | Mapped event types |
|---|---|---|
| events | yes | logon_success, logon_failed, account_created, group_member_added |
| processes | yes | process_created |
| network | yes | network_connection |
| powershell | yes | powershell_executed |
| files | yes | file_created |
| users | **no** — enrichment only (admin status, groups, creation time) | — |
| system | **no** — device context only | — |

## 7. Open points to confirm with the collector teammate

- [ ] Will process history come from Event 4688 / Sysmon, or only live snapshots? (`origin` tells us; history gives higher confidence.)
- [ ] Is PowerShell Script Block Logging (Event 4104) enabled on target machines, or do we only get PSReadLine history?
- [ ] Which folders/extensions does `files.json` cover?
- [ ] Is `manifest.json` generated by the preservation step? (Contract assumes yes.)
- [ ] Confirm UTC conversion happens in the collector.
- [ ] Confirm credential redaction in command lines.

## 8. Change log

| Date | Change |
|---|---|
| 2026-10-09 | `processes.command_line`: still a required field, but its value may now be `null` when the collector cannot retrieve it. All other required fields remain non-null. Relaxation only (no existing valid evidence becomes invalid), so `schema_version` stays `1.0`. |
