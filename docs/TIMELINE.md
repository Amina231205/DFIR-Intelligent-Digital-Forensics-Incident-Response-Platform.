# Sentinel DFIR — Timeline Reconstruction (Phase 4)

`build_case_timeline(folder)` returns one chronological `Timeline` for an evidence folder.

```text
validate → normalize (events, ordered, E-00001…) → build_timeline → [filter_timeline] → format / JSON
```

The timeline answers **what happened → when → on which device → under which user → what happened next**. It describes facts only; judging them is Phase 5 (detection).

## Guarantees

| Guarantee | How |
|---|---|
| Read-only | Events are never modified or re-ordered in place; entries hold copies of `details`; no file is written. |
| Deterministic | Order = Phase 3 `event_sort_key`: time, then source (events → processes → network → powershell → files), then numeric record number, then `record_id`. Input order never matters. |
| Lossless | Every `NormalizedEvent` field is on its entry; `entry.to_event()` rebuilds the exact original event. |
| Traceable | `event_id` (`E-00022`) and `evidence_id` (`PROC-0006`) are stable keys; `evidence_file` names the raw file. They never change when filtering. |
| Validated input only | `build_case_timeline` goes through `normalize_case`; invalid evidence raises `EvidenceNotValidError`. |

## `Timeline`

| Field | Meaning |
|---|---|
| `case_id` | Case; `null` only for an empty timeline built without one |
| `devices`, `users` | Distinct values, sorted case-insensitively (`users` ignores events with no user) |
| `start`, `end`, `duration_seconds` | First/last timestamp (UTC `Z`), span in seconds; `null`/`0.0` when empty |
| `event_count`, `counts_by_type`, `counts_by_source` | Totals, keys sorted |
| `entries` | `list[TimelineEntry]`, chronological |
| `get_by_event_id(id)`, `get_by_evidence_id(id)` | Lookup; `None` if absent |

## `TimelineEntry` (flat row, SQL table `TimelineEvents`)

| Field | Meaning |
|---|---|
| `sequence` | 1-based position **in this timeline** |
| `event_id`, `case_id`, `timestamp`, `event_type`, `source`, `device`, `user`, `evidence_id`, `details` | Copied unchanged from the `NormalizedEvent` |
| `evidence_file` | Raw file, e.g. `processes.json` |
| `summary` | Neutral one-line description (below) |
| `gap_from_previous_seconds` | Seconds since the previous entry; `null` for the first; `0.0` for ties |
| `offset_from_start_seconds` | Seconds since the first entry of this timeline |

## Summaries (facts only, ASCII only)

| Type | Template | Example |
|---|---|---|
| logon_success / logon_failed | `Successful\|Failed logon (<type>) for <user>[ from <ip>][: <reason>]` | `Failed logon (RemoteInteractive) for ahmed from 198.51.100.23: wrong password` |
| process_created | `Process created: <name> (PID n)[ by <user>][, parent <parent>]` | `Process created: powershell.exe (PID 6012) by ahmed, parent wscript.exe` |
| network_connection | `Outbound <proto> <local> -> <remote> (<process>[, <host>])` / `Inbound <proto> <remote> -> <local> (…)` | `Outbound TCP 10.20.0.15:49822 -> 203.0.113.77:443 (powershell.exe, files-sync.example.net)` |
| powershell_executed | `PowerShell script block by <user> (PID n)[, script <path>]` | |
| file_created | `File created: <path> (n bytes)[, owner <owner>]` | |
| account_created | `Account '<name>' created by <actor>` | `Account 'svc_helpdesk' created by ahmed` |
| group_member_added | `'<member>' added to group '<group>' by <actor>` | |
| other | `Windows event <id> in <channel> log` | |

Missing values read as `unknown user` / `unknown account` instead of raising. Command lines are deliberately left out of summaries (long, may hold secrets); they remain in `details`.

## Filtering — `filter_timeline(timeline, *, start, end, event_types, sources, users, devices)`

| Rule | Detail |
|---|---|
| Combination | Different criteria = AND; several values in one criterion = OR |
| `None` vs empty | `None` = no filter. An **empty** collection raises `ValueError` (it would silently match nothing) |
| Time range | `start`/`end` **inclusive**, timezone-aware (`datetime` or ISO string; offsets converted to UTC). Naive → error. `start > end` → error |
| Values | `event_types`, `sources`: enum or string, one or many; unknown value → `ValueError` listing the valid ones |
| `users`, `devices` | Case-insensitive. `users` matches the entry's `user` only (on account events that is the **actor**); entries with no user never match |
| Result | A **new** `Timeline`; input untouched; order kept; `event_id`/`evidence_id` unchanged; `sequence`, gaps, offsets, counts, `start`/`end` recomputed for the selection. A selection matching nothing is an empty timeline, not an error |

## Not in Phase 4

Detection, "is this IP external?", IOC extraction, MITRE mapping, session/burst grouping and any judgement about the events.
