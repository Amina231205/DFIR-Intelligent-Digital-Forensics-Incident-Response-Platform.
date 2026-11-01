"""Phase 6 tests: IOC configuration defaults, loading and validation."""

from __future__ import annotations

import dataclasses
import json

import pytest

from security.detection import IpClass, IpPolicy, PowerShellConfig
from security.ioc import IocConfig


class TestDefaults:
    def test_documented_defaults(self):
        c = IocConfig()
        assert c.ip_classes == ("public", "private", "documentation", "reserved")
        assert c.url_schemes == ("http", "https", "ftp")
        assert {"ps1", "vbs", "exe", "dll", "bat", "lnk"} <= set(c.suspicious_extensions)
        assert "txt" not in c.suspicious_extensions and "csv" not in c.suspicious_extensions
        assert c.system_path_prefixes == ("\\windows\\", "\\program files\\",
                                          "\\program files (x86)\\")
        assert c.ignored_usernames == ("system", "local service", "network service",
                                       "anonymous logon", "-")
        assert (c.decode_encoded_commands, c.link_file_records, c.max_scan_chars) == (
            True, True, 200_000)

    def test_loopback_linklocal_multicast_and_unspecified_are_never_iocs_by_default(self):
        assert not {"loopback", "link_local", "multicast", "unspecified"} & set(
            IocConfig().ip_classes)

    def test_writable_fragments_extend_the_detection_defaults(self):
        assert set(PowerShellConfig().writable_path_fragments) < set(
            IocConfig().writable_path_fragments)
        assert "\\windows\\tasks\\" in IocConfig().writable_path_fragments

    def test_the_external_attribute_uses_the_public_only_policy(self):
        assert IocConfig().ip_policy.external_classes == frozenset({IpClass.PUBLIC})

    def test_core_process_names_are_known(self):
        assert {"powershell.exe", "wscript.exe", "net.exe", "svchost.exe"} <= set(
            IocConfig().known_system_processes)


class TestLoading:
    def test_empty_dict_gives_defaults(self):
        assert IocConfig.from_dict({}) == IocConfig()

    def test_partial_override(self):
        c = IocConfig.from_dict({"ip_classes": ["public"], "url_schemes": ["https"]})
        assert c.ip_classes == ("public",) and c.url_schemes == ("https",)
        assert c.suspicious_extensions == IocConfig().suspicious_extensions

    def test_round_trip_through_json(self):
        original = IocConfig.from_dict({
            "ip_classes": ["public", "documentation"], "suspicious_extensions": [".PS1", "Exe"],
            "ip_policy": {"external_classes": ["public", "documentation"]},
            "link_file_records": False, "max_scan_chars": 5000})
        again = IocConfig.from_dict(json.loads(json.dumps(original.to_dict())))
        assert again == original

    def test_values_are_normalized(self):
        c = IocConfig(suspicious_extensions=(".PS1", " Exe "), ignored_usernames=("SYSTEM",),
                      writable_path_fragments=("/Temp/",))
        assert c.suspicious_extensions == ("ps1", "exe")
        assert c.ignored_usernames == ("system",)
        assert c.writable_path_fragments == ("\\temp\\",)

    def test_defaults_are_json_serializable(self):
        json.dumps(IocConfig().to_dict())

    def test_immutable(self):
        with pytest.raises(dataclasses.FrozenInstanceError):
            IocConfig().ip_classes = ()

    def test_rarely_useful_classes_can_be_enabled_explicitly(self):
        c = IocConfig.from_dict({"ip_classes": ["public", "loopback", "link_local"]})
        assert c.ip_classes == ("public", "loopback", "link_local")

    def test_ip_policy_can_opt_in_to_documentation(self):
        c = IocConfig.from_dict({"ip_policy": {"external_classes": ["public", "documentation"]}})
        assert c.ip_policy == IpPolicy.synthetic_demo()


INVALID = [
    ({"ip_classes": []}, "must not be empty"),
    ({"ip_classes": "public"}, "list of strings"),
    ({"ip_classes": ["invalid"]}, "unknown or unusable"),
    ({"ip_classes": ["missing"]}, "unknown or unusable"),
    ({"ip_classes": ["lan"]}, "unknown or unusable"),
    ({"url_schemes": []}, "must not be empty"),
    ({"suspicious_extensions": []}, "must not be empty"),
    ({"suspicious_extensions": [5]}, "non-empty strings"),
    ({"known_system_processes": "cmd.exe"}, "list of strings"),
    ({"decode_encoded_commands": "yes"}, "true or false"),
    ({"link_file_records": 1}, "true or false"),
    ({"max_scan_chars": 0}, "positive integer"),
    ({"max_scan_chars": True}, "positive integer"),
    ({"max_scan_chars": "100"}, "positive integer"),
    ({"ip_policy": {"external_classes": ["invalid"]}}, "never treated"),
    ({"ip_policy": {"other": 1}}, "only 'external_classes'"),
    ({"ip_policy": "public"}, "only 'external_classes'"),
    ({"suspicious_extension": ["ps1"]}, "unknown IOC option"),
]


class TestInvalid:
    @pytest.mark.parametrize("data, message", INVALID, ids=[str(d)[:55] for d, _ in INVALID])
    def test_invalid_settings_fail_loudly(self, data, message):
        with pytest.raises(ValueError, match=message):
            IocConfig.from_dict(data)

    @pytest.mark.parametrize("data", [[], "text", 5, None])
    def test_top_level_must_be_an_object(self, data):
        with pytest.raises(ValueError, match="JSON object"):
            IocConfig.from_dict(data)

    def test_direct_construction_is_validated_too(self):
        with pytest.raises(ValueError):
            IocConfig(max_scan_chars=0)
        with pytest.raises(ValueError):
            IocConfig(ip_policy="public")

    def test_unknown_option_message_lists_valid_options(self):
        with pytest.raises(ValueError, match="valid options: .*ip_classes"):
            IocConfig.from_dict({"ip_clases": ["public"]})
