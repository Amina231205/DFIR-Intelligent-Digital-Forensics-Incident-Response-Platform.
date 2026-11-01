"""Phase 6 tests: IOC parsing and validation helpers (pure functions)."""

from __future__ import annotations

import pytest
from detection_helpers import Factory, encode_command, findings_of

from security.detection import DetectionConfig, PowerShellConfig, run_detection
from security.ioc.parsers import (
    ParsedUrl, canonical_ip, extension_of, filename_of, find_ipv4_in_text, find_paths_in_text,
    find_urls_in_text, is_reserved_domain, is_system_path, is_valid_file_path, is_writable_path,
    normalize_domain, normalize_path_key, parse_hash, parse_url, text_variants)

SYSTEM = ("\\windows\\", "\\program files\\", "\\program files (x86)\\")
WRITABLE = ("\\temp\\", "\\users\\public\\", "\\appdata\\", "\\windows\\tasks\\")


class TestIpAddresses:
    @pytest.mark.parametrize("value, expected", [
        ("8.8.8.8", "8.8.8.8"), (" 203.0.113.77 ", "203.0.113.77"), ("::1", "::1"),
        ("2001:DB8::1", "2001:db8::1"), ("::ffff:8.8.8.8", "8.8.8.8"),
        ("999.1.1.1", None), ("010.0.0.1", None), ("1.2.3", None), ("-", None), ("", None),
        (None, None), (12345, None), ("not-an-ip", None), ("1.2.3.4/24", None)])
    def test_canonical_ip(self, value, expected):
        assert canonical_ip(value) == expected

    def test_addresses_in_text_are_validated(self):
        text = ("hit 203.0.113.9. then v1.2.3.4, 1.2.3.4.5, 999.1.1.1 and 10.0.19045.2006 "
                "and 8.8.8.8:53 ok")
        assert find_ipv4_in_text(text) == ["203.0.113.9", "8.8.8.8"]

    @pytest.mark.parametrize("text, expected", [
        ("ping 10.0.0.5", ["10.0.0.5"]), ("ip=10.0.0.5;", ["10.0.0.5"]),
        ("(10.0.0.5)", ["10.0.0.5"]), ("10.0.0.5, 10.0.0.6", ["10.0.0.5", "10.0.0.6"]),
        ("10.0.0.5 10.0.0.5", ["10.0.0.5"]), ("a10.0.0.5", []), ("10.0.0.5a", []),
        ("1.2.3.256", []), ("0.0.0.0", ["0.0.0.0"]), ("", [])])
    def test_text_boundaries(self, text, expected):
        assert find_ipv4_in_text(text) == expected


class TestDomains:
    @pytest.mark.parametrize("value, expected", [
        ("Files-Sync.Example.NET.", "files-sync.example.net"), ("a.co", "a.co"),
        ("sub.domain.example.org", "sub.domain.example.org"),
        ("bücher.de", "xn--bcher-kva.de"), ("xn--bcher-kva.de", "xn--bcher-kva.de"),
        ("a-b.example.com", "a-b.example.com"), ("1a.example.com", "1a.example.com")])
    def test_valid(self, value, expected):
        assert normalize_domain(value) == expected

    @pytest.mark.parametrize("value", [
        "a.b", "x", "", "   ", None, 5, "no_underscore.com", "-bad.example.com",
        "bad-.example.com", "host.123", "1.2.3.4", "a" * 64 + ".com", ("a." * 130) + "com",
        "double..dot.com", "spa ce.com", ".leading.com", "exa$mple.com", "a.b-c"])
    def test_invalid(self, value):
        assert normalize_domain(value) is None

    def test_label_length_limit_is_63(self):
        assert normalize_domain("a" * 63 + ".com") is not None
        assert normalize_domain("a" * 64 + ".com") is None

    @pytest.mark.parametrize("host, reserved", [
        ("example.net", True), ("files-sync.example.net", True), ("x.example.com", True),
        ("host.test", True), ("a.invalid", True), ("a.localhost", True),
        ("evil.com", False), ("notexample.net", False), ("example.net.evil.com", False)])
    def test_reserved_domains(self, host, reserved):
        assert is_reserved_domain(host) is reserved


class TestUrls:
    @pytest.mark.parametrize("raw, value, host, kind, creds", [
        ("https://Files.Example.COM/Path?a=1#f", "https://files.example.com/Path?a=1#f",
         "files.example.com", "domain", False),
        ("http://user:pw@Host.Example.com:8080/a).", "http://host.example.com:8080/a",
         "host.example.com", "domain", True),
        ("http://user@host.example.com/", "http://host.example.com/", "host.example.com",
         "domain", True),
        ("ftp://203.0.113.5/x", "ftp://203.0.113.5/x", "203.0.113.5", "ip", False),
        ("http://[2001:db8::1]:81/", "http://[2001:db8::1]:81/", "2001:db8::1", "ip", False),
        ("https://h.example.com/ok'", "https://h.example.com/ok", "h.example.com", "domain",
         False)])
    def test_valid_urls_are_normalized(self, raw, value, host, kind, creds):
        assert parse_url(raw) == ParsedUrl(value, raw.split(":")[0].lower(), host, kind, creds)

    @pytest.mark.parametrize("raw", [
        "http://bad_host/x", "http://h.example.com:99999/", "javascript://x.example.com",
        "file:///c:/x", "http://", "https://", "http://x/a b", 'http://x.example.com/a"b',
        "http://x.example.com/a\\b", "http://x.example.com/a\x01b", "http://1.2.3/x",
        "http://999.1.1.1/", "gopher://x.example.com/"])
    def test_invalid_urls_are_rejected(self, raw):
        assert parse_url(raw) is None

    def test_credentials_are_never_kept(self):
        assert "pw" not in parse_url("http://u:pw@h.example.com/").value

    def test_scheme_list_is_configurable(self):
        assert parse_url("ftp://h.example.com/", ("http", "https")) is None
        assert parse_url("ftp://h.example.com/", ("ftp",)) is not None

    def test_urls_found_in_text_stop_at_quotes_and_are_unique(self):
        text = ("$u='https://files-sync.example.net/stage/update_svc.ps1';Invoke-WebRequest "
                "-Uri $u; also http://a.example.com/x, http://a.example.com/x and "
                '"https://b.example.com/y" plus (ftp://c.example.com/z).')
        assert [u.value for u in find_urls_in_text(text)] == [
            "https://files-sync.example.net/stage/update_svc.ps1", "http://a.example.com/x",
            "https://b.example.com/y", "ftp://c.example.com/z"]

    def test_text_without_urls(self):
        assert find_urls_in_text("Get-Process; System.Net.WebClient") == []


class TestHashes:
    @pytest.mark.parametrize("value, expected", [
        ("a1" * 32, ("sha256", "a1" * 32)), ("A1" * 32, ("sha256", "a1" * 32)),
        (" " + "b2" * 20 + " ", ("sha1", "b2" * 20)),
        ("d41d8cd98f00b204e9800998ecf8427e", ("md5", "d41d8cd98f00b204e9800998ecf8427e"))])
    def test_valid(self, value, expected):
        assert parse_hash(value) == expected

    @pytest.mark.parametrize("value", [
        "0" * 64, "a" * 40, "f" * 32, "abc", "g" * 64, "a1" * 31, "a1" * 33, "", None, 123,
        "d41d8cd98f00b204e9800998ecf8427z"])
    def test_invalid(self, value):
        assert parse_hash(value) is None


class TestPaths:
    def test_paths_in_text(self):
        text = (r'powershell -File C:\Users\Public\update_svc.ps1;powershell '
                r'"C:\Users\Public\My Scripts\a b.ps1" -OutFile C:/Users/bob/x.exe '
                r'https://h.example.com/s_s.ps1 \\srv\share\t.dll')
        assert find_paths_in_text(text) == [
            r"C:\Users\Public\My Scripts\a b.ps1", r"C:\Users\Public\update_svc.ps1",
            "C:/Users/bob/x.exe", r"\\srv\share\t.dll"]

    @pytest.mark.parametrize("text, expected", [
        (r"run C:\a\b.ps1.", [r"C:\a\b.ps1"]), (r"(C:\a\b.ps1)", [r"C:\a\b.ps1"]),
        (r"-File:C:\a\b.ps1", [r"C:\a\b.ps1"]), (r"x C:\a\noextension", []),
        (r"C:\a\b.ps1,C:\a\c.ps1", [r"C:\a\b.ps1", r"C:\a\c.ps1"]),
        ("https://h.example.com/a.ps1", []), (r"relative\path\a.ps1", []), ("", [])])
    def test_boundaries(self, text, expected):
        assert find_paths_in_text(text) == expected

    def test_a_truncated_prefix_is_dropped_when_the_full_path_is_known(self):
        found = find_paths_in_text(r'"C:\Program Files\My Tool\run.exe"')
        assert found == [r"C:\Program Files\My Tool\run.exe"]

    @pytest.mark.parametrize("path, valid", [
        (r"C:\a\b.ps1", True), ("C:/a/b.ps1", True), (r"\\srv\share\t.dll", True),
        (r"C:\a\b", False), (r"C:\a\.", False), (r"a\b.ps1", False), ("b.ps1", False),
        (r"C:\a\b.verylongext", False), (r"C:\a\b<.ps1", False)])
    def test_valid_file_path(self, path, valid):
        assert is_valid_file_path(path) is valid

    def test_name_extension_and_key(self):
        assert filename_of(r"C:\x\Update_Svc.PS1") == "Update_Svc.PS1"
        assert filename_of("C:/x/a.ps1") == "a.ps1"
        assert extension_of(r"C:\x\Update_Svc.PS1") == "ps1"
        assert extension_of(r"C:\x\noext") == ""
        assert normalize_path_key("C:/Users/Public/A.PS1") == r"c:\users\public\a.ps1"
        assert normalize_path_key(r"C:\Users\Public\..\..\Windows\X.exe") == r"c:\windows\x.exe"

    @pytest.mark.parametrize("path, system", [
        (r"C:\Windows\System32\wscript.exe", True), (r"C:\WINDOWS\explorer.exe", True),
        (r"D:\Program Files\Tool\t.exe", True), (r"C:\Program Files (x86)\T\t.exe", True),
        (r"C:\Windows\Temp\x.exe", False),                 # user-writable beats system
        (r"C:\Windows\Tasks\x.exe", False),
        (r"C:\Users\b\AppData\Roaming\Microsoft\Windows\Start Menu\e.vbs", False),
        (r"C:\Users\Public\update.ps1", False), (r"C:\Users\Public\..\..\Windows\x.exe", True),
        (r"C:\WindowsApps\x.exe", False), (r"\\srv\share\x.exe", False), ("x.exe", False)])
    def test_system_paths_are_anchored(self, path, system):
        assert is_system_path(path, SYSTEM, WRITABLE) is system

    def test_writable_paths(self):
        assert is_writable_path(r"C:\Users\bob\AppData\Local\Temp\a.ps1", WRITABLE)
        assert not is_writable_path(r"C:\IT\Scripts\a.ps1", WRITABLE)
        assert not is_writable_path(r"C:\temporary\a.ps1", WRITABLE)


B64 = encode_command("Invoke-WebRequest http://h.example.com/x")


class TestEncodedTextVariants:
    def test_decoded_text_is_added_with_a_label(self):
        variants = text_variants(f"powershell.exe -NoProfile -enc {B64}", "command_line")
        assert [label for label, _ in variants] == ["command_line", "command_line (decoded)"]
        assert "Invoke-WebRequest" in variants[1][1]

    def test_decoding_can_be_switched_off(self):
        assert len(text_variants(f"powershell -enc {B64}", "x", decode=False)) == 1

    @pytest.mark.parametrize("fragment", ["-e notbase64!", "-enc short", "-enc", "-w hidden",
                                          f"-EncodedCommandX {B64}", "-ZZZZZZZZZZZZ"])
    def test_nothing_is_decoded_without_a_real_encoded_command(self, fragment):
        assert len(text_variants(f"powershell {fragment}", "x")) == 1

    def test_undecodable_payload_does_not_raise(self):
        assert len(text_variants("powershell -enc ZZZZZZZZZZZZ", "x")) == 1

    def test_decoding_is_one_level_deep(self):
        outer = encode_command(f"powershell -enc {B64}")
        variants = text_variants(f"powershell -enc {outer}", "x")
        assert len(variants) == 2                      # outer decoded; inner is not


class TestParityWithDetection:
    """IOC extraction and DET-002 must agree on what an encoded command looks like."""

    SPELLINGS = ["-enc", "-e", "-ec", "-en", "-EncodedCommand", "-ENCODEDCOMMAND",
                 "-EncodedCommand:", "-enco", "-encodedcommand", "-x", "-ex", "-w",
                 "-EncodedCommandX", "-encodedcommands"]

    @pytest.mark.parametrize("flag", SPELLINGS)
    def test_same_decision_as_the_powershell_rule(self, flag):
        value = encode_command("Get-Date")
        command = f"powershell.exe {flag}{value}" if flag.endswith(":") \
            else f"powershell.exe {flag} {value}"
        f = Factory()
        f.process(0, 500, command_line=command)
        result = run_detection(
            f.timeline(), DetectionConfig(powershell=PowerShellConfig(min_indicators=1)),
            now=__import__("detection_helpers").NOW)
        det002 = any(m["indicator"] == "encoded_command"
                     for x in findings_of(result, "DET-002") for m in x.matched_indicators)
        ioc = len(text_variants(command, "command_line")) == 2
        assert ioc == det002, flag
