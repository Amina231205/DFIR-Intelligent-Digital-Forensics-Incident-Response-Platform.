# Sentinel DFIR — IOC Extraction (Phase 6)

Turns the evidence cited by detection findings into a validated, de-duplicated list of indicators of compromise, each traceable to the raw records it came from.

```text
validate -> normalize -> timeline -> detection -> [ IOC extraction ] -> IOCs (+ findings with their iocs filled in)
```

An IOC is an **observable that appears in the evidence of a finding**. It is not a verdict: a public IP, a domain or a username is listed because it occurs in suspicious activity, not because it is proven malicious. MITRE mapping, investigation reports and backend storage are later phases.

## Guarantees

| Guarantee | How |
|---|---|
| Read-only | Timeline and detection inputs are never modified; findings are returned as **copies** with `iocs` filled in; nothing is written |
| Deterministic | Same inputs give byte-identical output, whatever the event order; no clock is used |
| Validated | Regex only finds *candidates*; each one is checked with `ipaddress`, `urllib.parse`, `ntpath` or explicit rules before it can become an IOC |
| Traceable | Every IOC lists every occurrence: record id, raw file, field, timestamp, role, and the finding(s) it relates to |
| Invalid is not silent | An invalid structured value (bad IP, hostname, hash) is reported in `data_gaps`; a missing one is simply absent |
| No secrets stored | URL credentials are removed; encoded payloads are decoded only to look for indicators and never copied |

## Scope: which evidence is examined

Only evidence a finding **cites**:

1. its `supporting_events`, and
2. the records its `context.correlated_records` lists (same device, PID and time window, e.g. a connection by the PowerShell process even when the IP policy does not call it external).

Benign traffic that no finding mentions (e.g. the Chrome connection in the sample) never becomes an IOC. One extra link exists: a `files.json` record is added when its path **equals** (after normalization: case, slash style, `..`) the path of an extracted filename IOC, and it brings its SHA-256. The same file name in another folder is never linked.

## What is extracted

| Type | From | Rules |
|---|---|---|
| `ip` | logon `source_ip`; `remote_address` of connections; valid IPv4 in command/script text; URL hosts | Classified with the detection IP policy. Kept classes: `ip_classes` (default public, private, documentation, reserved). Loopback, link-local, multicast and unspecified are off by default. `local_address` is never extracted. IPv4-mapped IPv6 becomes IPv4. Invalid structured value -> data gap; invalid text candidates (`999.1.1.1`, `v1.2.3.4`, `1.2.3.4.5`) are ignored |
| `domain` | `remote_hostname`; host of URLs | Lowercase ASCII (IDNA/punycode); 2+ labels of 1-63 letters/digits/hyphens, no leading/trailing hyphen, no underscore, alphabetic TLD >= 2, not an IP. Names under `example.com/net/org` and `.test/.example/.invalid/.localhost` are labelled `reserved_for_documentation` |
| `url` | process command lines, PowerShell text and host application, decoded `-EncodedCommand` text | `http`/`https`/`ftp` (`url_schemes`); valid host; credentials removed; trailing punctuation dropped; no whitespace, quotes or control characters |
| `filename` | paths in command lines/script text, `script_path`, `file_created` records | Drive-letter or UNC path with an extension in `suspicious_extensions` **and** not in a protected system folder. The value is the file name; full paths are in `attributes.paths` and each occurrence |
| `hash` | `sha256` of linked file records and of non-system processes | 64/40/32 hex digits -> sha256/sha1/md5, lowercased. All-same-character values (`000...`) are placeholders and rejected |
| `process` | `process_created` records | Executable path outside protected folders, or (no path) a name not in `known_system_processes`. A system name in a user folder (`C:\Users\Public\svchost.exe`) **is** reported |
| `username` | event `user`, created account (`target_user`), group member (`member_name`) | Machine accounts (`...$`) and `ignored_usernames` are skipped. Roles are kept in `attributes.roles` |

**Protected system folders:** a path is "system" when, after normalization, it starts with `\windows\`, `\program files\` or `\program files (x86)\` after the drive letter. The test is anchored, so `...\AppData\Roaming\Microsoft\Windows\...` is not system; a path that also matches a user-writable fragment (`\temp\`, `\windows\tasks\`) is never system; `C:\Users\Public\..\..\Windows\x.exe` is resolved before checking.

**Not extracted from free text** (too many false positives): bare domain names (`System.Net.WebClient` looks like one), IPv6 addresses, bare file names without a directory. IPv6 is still extracted from structured fields.

## Output

`IocResult`: `case_id`, `iocs`, `findings` (copies with `iocs` ids), `counts_by_type`, `data_gaps`, `config`.

`IOC`: `ioc_id` (`IOC-001`...), `type`, `value`, `source` / `evidence_id` / `timestamp` (the **earliest** occurrence), `context` (role of that occurrence, plus "(+N more occurrence(s))"), `related_findings`, `first_seen`, `last_seen`, `attributes`, `occurrences`.

One IOC per unique (type, value). IDs follow first-seen time, then type, then value. `occurrences[]` entries: `event_id`, `evidence_id`, `evidence_file`, `field` (e.g. `command_line (decoded)`), `timestamp`, `context`, plus `path`, `port`, `direction`, `pid` where relevant. `related_findings` is the union over all occurrences plus, for file records linked by path, the findings that cited the path.

| Type | `attributes` |
|---|---|
| ip | `ip_class`, `external` (per IP policy; `null` if unknown) |
| domain | `reserved_for_documentation` |
| url | `scheme`, `host`, `host_type`, `credentials_removed` |
| filename | `extension`, `paths` |
| hash | `algorithm`, `file_paths` |
| process | `basis` |
| username | `roles` |

## Configuration (`IocConfig`)

| Option | Default |
|---|---|
| `ip_classes` | public, private, documentation, reserved |
| `ip_policy.external_classes` | public (only for the `external` attribute; same default as detection) |
| `url_schemes` | http, https, ftp |
| `suspicious_extensions` | ps1, psm1, vbs, vbe, js, jse, wsf, hta, bat, cmd, exe, dll, scr, com, lnk, msi, jar, sys, cpl, reg, iso, img, zip, rar, 7z, docm, xlsm, pptm, dotm |
| `writable_path_fragments` | the detection defaults plus `\windows\tasks\` |
| `system_path_prefixes` | `\windows\`, `\program files\`, `\program files (x86)\` |
| `known_system_processes` | common Windows system and shell processes (see `config.py`) |
| `ignored_usernames` | system, local service, network service, anonymous logon, - |
| `decode_encoded_commands` | true |
| `link_file_records` | true |
| `max_scan_chars` | 200000 |

Settings are validated on creation (`ValueError` for typos, wrong types, empty lists, unknown classes); `missing` and `invalid` can never be IP classes. Rarely useful classes such as `loopback` can be enabled explicitly.

## Limitations

* Only cited evidence is examined, so an indicator that appears solely in evidence no finding references is not extracted.
* `username` IOCs include the account the activity ran under, which is often the **victim** account; roles say what each account did.
* Documentation-range IPs and `example.*` domains are extracted (they are the indicators in synthetic evidence) but labelled; they are not "external" under the default policy.
* Free-text IPv4 can still match version-like values that happen to be valid (`1.0.0.0`).
* URL query strings are kept as found (only credentials are removed); an unquoted path containing spaces is not recognised unless quoted.
* Hashes come from structured fields only (no hash guessing in free text); a file record is linked by exact path only.
* `known_system_processes` and the system-folder list are static lists, not a baseline of the actual machine.
* Decoding goes one level deep; heavily obfuscated scripts can hide indicators.

## Python API

```python
from security.ioc import extract_case_iocs, extract_iocs, IocConfig
from security.detection import run_detection
from security.timeline import build_case_timeline

result = extract_case_iocs("security/sample_evidence/INC-001")        # whole pipeline
for ioc in result.iocs:
    print(ioc.ioc_id, ioc.type.value, ioc.value, ioc.related_findings, len(ioc.occurrences))
for finding in result.findings:                                        # copies, with iocs filled in
    print(finding.finding_id, finding.iocs)
print(result.data_gaps)                                                # invalid values not extracted

timeline = build_case_timeline("security/sample_evidence/INC-001")     # or reuse earlier stages
detection = run_detection(timeline)
result = extract_iocs(timeline, detection, IocConfig(ip_classes=("public",)))
```

`EvidenceNotValidError` for invalid evidence; `TypeError`/`ValueError` for bad arguments or a timeline and detection from different cases. `result.to_dict()` is JSON-safe.

## Command line

```bash
python -m security.ioc security/sample_evidence/INC-001
python -m security.ioc security/sample_evidence/INC-001 --json --now 2026-10-09T12:00:00Z
python -m security.ioc security/sample_evidence/INC-001 --ioc-config my_ioc.json
python -m security.ioc security/sample_evidence/INC-001 --config my_detection.json
```

`my_ioc.json` overrides only what it names, e.g. `{"ip_classes": ["public"], "suspicious_extensions": ["ps1", "exe"]}`. `--config` is the detection configuration (findings determine the scope). Exit codes: `0` ran, `1` evidence failed validation, `2` invalid option or configuration. Output is ASCII only.

## Where later phases fit

`IOC.type` and `value` already map onto standard indicator types, so a later STIX/TAXII export or enrichment can consume `IocResult` without changing extraction. Neither is implemented. MITRE ATT&CK mapping (Phase 7) and the investigation engine (Phase 8) will read `findings[].iocs`.
