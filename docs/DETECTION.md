# Sentinel DFIR — Detection Engine (Phase 5)

Three deterministic, explainable rules run over the Phase 4 timeline and return findings that point back to the raw evidence.

```text
validate -> normalize -> timeline -> [ DET-001 -> DET-002 -> DET-003 ] -> findings (+ data gaps)
```

A finding says **which stated conditions matched**. It is not a verdict: none of these rules proves an attack, and the wording says so ("indicators are heuristics, not proof"). IOC extraction, MITRE mapping, recommended next steps and reports are later phases, so `iocs`, `mitre_techniques` and `recommended_next_steps` stay empty.

## Guarantees

| Guarantee | How |
|---|---|
| Read-only | Events are copied out of the timeline; nothing is written; config objects are frozen |
| Deterministic | Same timeline + config + `now` gives byte-identical output, whatever the input event order. Only `generated_at` / `detected_at` depend on the clock (pass `now` to fix it) |
| Traceable | Every finding lists supporting `E-…` event ids, raw `evidence_sources` (record ids) and `evidence_files`; every matched indicator names its record |
| No duplicates | A rule's findings are built so a failure/process/creation belongs to one finding; the engine also drops a finding whose rule and supporting-event set already exist (`duplicates_removed`) |
| Missing data is not a negative | Each rule reports `data_gaps` for what it could not evaluate. 0 findings **and** 0 gaps is a real negative; 0 findings with gaps is "not ruled out" |
| Wrong settings fail loudly | Config is validated on creation; typos, bad types and invalid regexes raise `ValueError` |

## Finding fields

`finding_id` (`F-001`…, assigned by rule order then time, so later rules can cite earlier findings), `rule_id`, `rule_name`/`title`, `severity`, `confidence`, `device`, `user`, `description`, `reason`, `detected_at`, `first_seen`/`last_seen` (span of all supporting events), `supporting_events`, `evidence_sources`, `evidence_files`, `matched_indicators` (list of dicts), `severity_factors`, `confidence_factors`, `context` (grouping, thresholds, correlation, links), plus the empty `iocs`, `mitre_techniques`, `recommended_next_steps`.

Records that are not timeline events but were relied on (the `users.json` account behind an "is administrator" fact) are cited in `evidence_sources` / `evidence_files` too.

## Severity and confidence

**Severity** starts at the rule's base level and rises one step per documented aggravating factor. It is capped at **High**; Critical is reserved for confirmed impact and is never assigned automatically. Every step is listed in `severity_factors`.

**Confidence** is how sure we are that the rule's *stated conditions are genuinely met and linked correctly*. It is **not** the probability of malicious intent.

| Level | Meaning |
|---|---|
| High | Conditions met on direct evidence with a clear margin or an independent corroboration from a different evidence file |
| Medium | Conditions met on direct evidence, near the minimum, no independent corroboration |
| Low | Conditions met, but a required link is weak/indirect or depends on missing fields |

## IP classification and the "external" policy

Classification uses `ipaddress` but not `is_private`/`is_global` alone: Python calls documentation ranges "private" and multicast "global". First match wins:

| Class | Matches | External by default |
|---|---|---|
| `missing` | `None`, `""`, `"-"` | unknown |
| `invalid` | not an IP address (text, wrong type, `999.1.1.1`, `010.0.0.1`) | unknown |
| `unspecified` | `0.0.0.0`, `::` | no |
| `loopback` | `127.0.0.0/8`, `::1` | no |
| `link_local` | `169.254.0.0/16`, `fe80::/10` | no |
| `multicast` | `224.0.0.0/4`, `ff00::/8` | no |
| `documentation` | `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32` | **no** (opt-in only, see below) |
| `private` | `10/8`, `172.16/12`, `192.168/16`, `fc00::/7` | no |
| `public` | globally routable | **yes** |
| `reserved` | everything else (CGNAT `100.64/10`, broadcast, `240/4`, …) | no |

IPv4-mapped IPv6 (`::ffff:a.b.c.d`) is classified as the IPv4 address. "External" means "outside the local/private network", **not** "malicious": a public address alone never produces a finding. An address that is `missing` or `invalid` is *unknown* (neither internal nor external) and becomes a data gap.

**Default: only `public` (genuinely public, globally routable) addresses are external.** Documentation ranges stay classified as `documentation`, are never reported as `public`, and are **not** external unless you opt in explicitly.

**Synthetic demonstrations (opt-in).** The sample case INC-001 uses documentation addresses as stand-ins for internet hosts. To make a demonstration treat them as external, enable it deliberately; it is never the default:

```json
{"powershell": {"ip_policy": {"external_classes": ["public", "documentation"]}}}
```

That exact file ships as `examples/detection_synthetic_demo.json` (`--config examples/detection_synthetic_demo.json`); in Python use `IpPolicy.synthetic_demo()`. The enabled classes are recorded in every DET-002 finding (`context.external_classes`) and in `DetectionResult.config`, so a result always shows which policy produced it.

**Effect on the sample case.** With the default policy the connections to `203.0.113.77` are still *correlated* with the PowerShell processes (same device, PID and window, listed in `context.correlated_records`) but do not count as `external_connection`. Both PowerShell findings still fire: PID 6012 on 6 indicators and PID 6188 on 2 (the default minimum). With the opt-in they gain `external_connection` (7 and 3 indicators).

## DET-001 — Possible Brute-Force Logon Attempts

**What is counted.** Only `logon_failed` events. Each is grouped by **(device, target account, source address)**, all case-insensitive. Target account = event `user` (`TargetUserName`); source = `details.source_ip` (`IpAddress`). Failures with a different account, source or device are never combined. A failure with no account is skipped; one with no source address is skipped (the "same source" condition cannot be checked) unless `include_events_without_source` is on. Both cases are reported under `data_gaps`.

**Burst.** Inside a group, sorted by time, a burst is any run of at least `threshold` failures whose first and last timestamps are at most `window_seconds` apart (**both inclusive**). Overlapping qualifying windows merge into one burst, so a long attack gives one finding. Each failure belongs to at most one finding.

**Success correlation.** A `logon_success` is linked only if it has the same device, account **and** source address (known on both sides) and happens between the last failure and `success_window_seconds` later. If a candidate success has no source address the status is `unverifiable`, not `no`. Result in `context.followed_by_successful_logon`: `yes` / `no` / `unverifiable`.

| | Default | Rule |
|---|---|---|
| `threshold` | 5 | failures needed in one window |
| `window_seconds` | 120 | max span first-to-last failure |
| `success_window_seconds` | 300 | how long after the last failure a success counts |
| `include_events_without_source` | false | also group failures with no source address |

Severity: **Medium**, +1 (High) if followed by a successful logon from the same source. Confidence: **Medium**; High if count >= 2 x threshold; **Low** if the group has no source address. Source address class (`context.source_ip_class`) is recorded but never changes severity or confidence.

## DET-002 — Suspicious PowerShell Activity

Running PowerShell is never a finding. A finding needs **`min_indicators` (default 2) distinct indicators** on **one PowerShell execution context**.

**Execution context** = one PowerShell process, identified by (device, PID). The anchor is a `process_created` event whose name is in `powershell_process_names`; if the PID is reused later, each start is its own context. With no process record, the first PowerShell script-block record for that PID becomes the anchor (and a data gap says command line and parent are unavailable). Attached to a context, only when **all** hold: same device, same PID, at/after the anchor and at most `correlation_window_seconds` later, user matches when both sides have one, and (connections) the process name is PowerShell-named and the direction is outbound.

| Indicator | Matches |
|---|---|
| `encoded_command` | `-EncodedCommand`, any prefix (`-e`, `-enc`…) or `-ec`, followed by a Base64 value (the payload is never copied into the finding) |
| `hidden_window` | `-WindowStyle`/`-w…` with a value in `hidden_window_values` (`hidden`, `1`) |
| `execution_policy_bypass` | `-ExecutionPolicy`/`-ep` with a value in `execution_policy_values` (`bypass`, `unrestricted`) |
| `download_cradle` | script text matches a `download_patterns` regex (`Invoke-WebRequest`, `iwr`, `Net.WebClient`, `DownloadString`, …) |
| `invoke_expression` | script text matches `invoke_expression_patterns` (`Invoke-Expression`, `iex`) |
| `unusual_parent` | parent process name in `unusual_parents` |
| `user_writable_script_path` | `-File` argument or `script_path` containing a `writable_path_fragments` entry |
| `external_connection` | an attached outbound connection to an address the IP policy calls external |

Texts scanned: the process command line, each attached record's script text and launching command line, and the decoded form of any Base64 `-EncodedCommand` argument (one level; read only, nothing is executed). `-NoProfile` is deliberately **not** an indicator: legitimate scheduled scripts use it. Only `-` parameters are parsed.

Severity: **Medium** (Low if only one indicator is required and matched), +1 if `external_connection` matched, +1 if the acting account is an administrator (`users.json`); cap High. Confidence: **High** if >= 3 indicators from >= 2 evidence files; **Medium** if (>= 2 and >= 2 files) or >= 3; else **Low**.

| Option | Default |
|---|---|
| `min_indicators` | 2 |
| `enabled_indicators` | all eight |
| `correlation_window_seconds` | 900 |
| `powershell_process_names` | powershell.exe, pwsh.exe, powershell_ise.exe |
| `unusual_parents` | wscript.exe, cscript.exe, mshta.exe, winword.exe, excel.exe, powerpnt.exe, outlook.exe, wmiprvse.exe |
| `execution_policy_values` / `hidden_window_values` | bypass, unrestricted / hidden, 1 |
| `download_patterns`, `invoke_expression_patterns`, `writable_path_fragments` | see `config.py` |
| `ip_policy.external_classes` | public (documentation only by explicit opt-in) |

## DET-003 — Suspicious Account Creation

For each `account_created` event (Windows 4720). **Actor** = who performed it (`user`, `SubjectUserName`) -> `Finding.user`. **Target** = the new account (`details.target_user`) -> `context.target_account`. They are never mixed: the brute-force link below uses the actor, not the target.

**Default firing condition** (`require_privileged_target`, `min_context_indicators`):

1. **Privileged target:** a `group_member_added` event on the same device for the target, into a group in `privileged_groups`, within `group_add_window_seconds` *after* the creation; or `users.json` (`target_user_context`) lists it as administrator. Answer: `yes` / `no` / `unknown`. `unknown` (target absent from `users.json` and no group event) is a data gap, never "no".
2. **At least one context indicator**, each needing an exact link:
   * `process_chain_linked_to_powershell_finding` — the process that ran the creation command (same device and actor, started at most `creating_process_window_seconds` before, command line naming the target and matching `creation_command_patterns`) has an ancestor (`ppid -> pid`, within `ancestry_window_seconds`, up to `max_ancestry_depth`) that belongs to a DET-002 finding.
   * `actor_account_targeted_by_bruteforce` — a DET-001 finding on the same device for an account with the **actor's** name, followed by a successful logon at most `context_window_seconds` before the creation. This link is **account-level**: normalized events carry no logon-session id, so it cannot prove the creation happened in that session.

Severity: **Low** + 1 (privileged target) + 1 per context indicator, cap High. Confidence: **High** if independently corroborated (`users.json` `created_at` within `snapshot_tolerance_seconds` of the event, or a process/script record shows the creation command naming the target); **Low** if the only context is the account-level brute-force link and nothing corroborates; else **Medium**.

Context indicators need DET-001/DET-002 to have run. If they did not, or no creating process was found, the indicator is reported as a data gap.

| Option | Default |
|---|---|
| `privileged_groups` | administrators |
| `group_add_window_seconds` | 600 |
| `creating_process_window_seconds` | 60 |
| `ancestry_window_seconds` / `max_ancestry_depth` | 3600 / 4 |
| `context_window_seconds` | 1800 |
| `snapshot_tolerance_seconds` | 60 |
| `require_privileged_target` / `min_context_indicators` | true / 1 (0-2 allowed) |
| `creation_command_patterns` | `net user ... /add`, `New-LocalUser`/`Add-LocalUser`, `New-ADUser` |

## Correlation policy

Records are linked across sources **only** through fields that support the link, plus a bounded time window. Closeness in time alone never links anything.

| Link | Required |
|---|---|
| PowerShell record / connection -> process | same device, same PID, within the window after the process start, user compatible, PowerShell-named process (connections), outbound |
| Success logon -> failure burst | same device, same account, same source address, after the last failure, within the window |
| Group add -> account creation | same device, member name = target, privileged group, within the window after |
| Creating process -> creation event | same device, same actor, command names the target and matches a pattern, within the window before |
| Parent process | `ppid -> pid`, same device, user compatible, not later than the child, within the window, depth-limited |
| Actor -> brute-force finding | same device, finding's account = **actor**, successful logon earlier within the window (account-level) |

Not linked: other PID / device / user, another process reusing a PID (name mismatch or outside the window), inbound traffic, events that are merely close in time. `context.correlated_records` lists the basis of every link.

## Limitations

* No logon-session id, so account-level links cannot be tied to one session.
* Process end times are unknown: the PID-reuse guard is a time window, not a lifetime.
* PowerShell command parsing covers `-` parameters only; heavy obfuscation, string concatenation or nested encodings beyond one level are not decoded.
* Indicators are explicit lists and patterns, so they are only as good as the configuration; an attacker can avoid them, and legitimate tools can match them.
* DET-002 raises a separate finding for each PowerShell process (a parent and child can both fire); relating findings to each other is the investigation phase.
* Event times come from the collector and are trusted as given (clock skew is not modelled).
* A finding's time range includes a linked success logon, so it can extend past the last failure.

## Python API

```python
from datetime import datetime, timezone
from security.detection import detect_case, run_detection, format_detection, DetectionConfig
from security.timeline import build_case_timeline

config = DetectionConfig.from_dict({"brute_force": {"threshold": 3, "window_seconds": 60}})
result = detect_case("security/sample_evidence/INC-001", config=config,
                     now=datetime(2026, 10, 9, 12, 0, tzinfo=timezone.utc))

timeline = build_case_timeline("security/sample_evidence/INC-001")   # or reuse a timeline
result = run_detection(timeline, rule_ids=["DET-001", "DET-002"])

for finding in result.findings:
    print(finding.finding_id, finding.rule_id, finding.severity.value, finding.confidence.value)
    print(finding.supporting_events, finding.evidence_sources, finding.matched_indicators)
for rule in result.rules:
    print(rule.rule_id, rule.events_considered, rule.findings, rule.data_gaps)
print(format_detection(result))       # ASCII text; result.to_dict() is JSON-safe
```

`EvidenceNotValidError` is raised for invalid evidence; `ValueError`/`TypeError` for bad arguments.

## Command line

```bash
python -m security.detection security/sample_evidence/INC-001
python -m security.detection security/sample_evidence/INC-001 --json --now 2026-10-09T12:00:00Z
python -m security.detection security/sample_evidence/INC-001 --rule DET-001 --rule DET-002
python -m security.detection security/sample_evidence/INC-001 --config my_config.json
python -m security.detection security/sample_evidence/INC-001 --config examples/detection_synthetic_demo.json   # explicit synthetic-demo opt-in
```

`my_config.json` overrides only what it names:

```json
{
  "brute_force": {"threshold": 3, "window_seconds": 60},
  "powershell": {"min_indicators": 3, "ip_policy": {"external_classes": ["public"]}},
  "account_creation": {"privileged_groups": ["Administrators", "Backup Operators"]}
}
```

Exit codes: `0` ran (findings are results, not errors), `1` evidence failed validation, `2` invalid option or configuration. Output is ASCII only.

## Adding a rule

Subclass `Rule` (`rule_id`, `name`, `evaluate(context) -> RuleOutput`), build findings with `build_finding(...)`, append the class to `RULE_CLASSES` in `rules.py`. The engine assigns ids, removes duplicates and builds the summary; the report needs no change. A rule must not modify `context.events` and must only return findings carrying its own `rule_id`.
