"""Phase 5 tests: detection configuration defaults, loading and validation."""

from __future__ import annotations

import dataclasses
import json

import pytest

from security.detection import (
    AccountCreationConfig, BruteForceConfig, DetectionConfig, IpClass, IpPolicy,
    PowerShellConfig)
from security.detection.config import POWERSHELL_INDICATORS


class TestDocumentedDefaults:
    def test_brute_force_defaults(self):
        c = BruteForceConfig()
        assert (c.threshold, c.window_seconds, c.success_window_seconds,
                c.include_events_without_source) == (5, 120, 300, False)

    def test_powershell_defaults(self):
        c = PowerShellConfig()
        assert c.min_indicators == 2 and c.correlation_window_seconds == 900
        assert c.enabled_indicators == POWERSHELL_INDICATORS
        assert "wscript.exe" in c.unusual_parents and "explorer.exe" not in c.unusual_parents
        assert c.execution_policy_values == ("bypass", "unrestricted")
        assert c.ip_policy == IpPolicy()

    def test_default_policy_counts_only_public_addresses_as_external(self):
        assert PowerShellConfig().ip_policy.external_classes == frozenset({IpClass.PUBLIC})
        assert DetectionConfig().to_dict()["powershell"]["ip_policy"] == {
            "external_classes": ["public"]}

    def test_documentation_ranges_need_an_explicit_opt_in(self):
        c = DetectionConfig.from_dict({"powershell": {"ip_policy": {
            "external_classes": ["public", "documentation"]}}})
        assert c.powershell.ip_policy == IpPolicy.synthetic_demo()
        assert c != DetectionConfig()

    def test_noprofile_is_not_an_indicator(self):
        assert not any("noprofile" in i for i in POWERSHELL_INDICATORS)

    def test_account_creation_defaults(self):
        c = AccountCreationConfig()
        assert c.privileged_groups == ("administrators",)
        assert (c.group_add_window_seconds, c.creating_process_window_seconds,
                c.ancestry_window_seconds, c.max_ancestry_depth,
                c.context_window_seconds, c.snapshot_tolerance_seconds) == (
            600, 60, 3600, 4, 1800, 60)
        assert c.require_privileged_target is True and c.min_context_indicators == 1


class TestLoading:
    def test_empty_dict_gives_defaults(self):
        assert DetectionConfig.from_dict({}) == DetectionConfig()

    def test_partial_override_keeps_other_defaults(self):
        c = DetectionConfig.from_dict({"brute_force": {"threshold": 3}})
        assert c.brute_force.threshold == 3 and c.brute_force.window_seconds == 120
        assert c.powershell == PowerShellConfig()

    def test_round_trip_through_json(self):
        original = DetectionConfig.from_dict({
            "brute_force": {"threshold": 7, "include_events_without_source": True},
            "powershell": {"min_indicators": 3, "ip_policy": {"external_classes": ["public"]},
                           "enabled_indicators": ["hidden_window", "encoded_command",
                                                  "external_connection"]},
            "account_creation": {"privileged_groups": ["Administrators", "Backup Operators"],
                                 "min_context_indicators": 0}})
        again = DetectionConfig.from_dict(json.loads(json.dumps(original.to_dict())))
        assert again == original

    def test_defaults_are_json_serializable(self):
        json.dumps(DetectionConfig().to_dict())

    def test_text_options_are_normalized(self):
        c = DetectionConfig.from_dict({
            "powershell": {"unusual_parents": ["WScript.EXE"]},
            "account_creation": {"privileged_groups": [" Administrators "]}})
        assert c.powershell.unusual_parents == ("wscript.exe",)
        assert c.account_creation.privileged_groups == ("administrators",)

    def test_enabled_indicators_keep_canonical_order(self):
        c = PowerShellConfig(enabled_indicators=("external_connection", "encoded_command"))
        assert c.enabled_indicators == ("encoded_command", "external_connection")

    def test_forward_slash_path_fragments_are_normalized(self):
        c = PowerShellConfig(writable_path_fragments=("/Users/Public/",))
        assert c.writable_path_fragments == ("\\users\\public\\",)

    def test_config_objects_are_immutable(self):
        with pytest.raises(dataclasses.FrozenInstanceError):
            BruteForceConfig().threshold = 1
        with pytest.raises(dataclasses.FrozenInstanceError):
            DetectionConfig().brute_force = BruteForceConfig()

    def test_ip_policy_loaded_from_classes(self):
        c = DetectionConfig.from_dict(
            {"powershell": {"ip_policy": {"external_classes": ["public", "private"]}}})
        assert c.powershell.ip_policy.external_classes == frozenset(
            {IpClass.PUBLIC, IpClass.PRIVATE})


INVALID = [
    ({"brute_force": {"threshold": 0}}, "threshold must be a positive integer"),
    ({"brute_force": {"threshold": -3}}, "threshold must be a positive integer"),
    ({"brute_force": {"threshold": "5"}}, "threshold must be a positive integer"),
    ({"brute_force": {"threshold": 2.5}}, "threshold must be a positive integer"),
    ({"brute_force": {"threshold": True}}, "threshold must be a positive integer"),
    ({"brute_force": {"threshold": None}}, "threshold must be a positive integer"),
    ({"brute_force": {"window_seconds": 0}}, "window_seconds must be a positive integer"),
    ({"brute_force": {"success_window_seconds": -1}}, "success_window_seconds"),
    ({"brute_force": {"include_events_without_source": "yes"}}, "true or false"),
    ({"brute_force": {"treshold": 3}}, "unknown option"),
    ({"brute_force": [1, 2]}, "must be a JSON object"),
    ({"nope": {}}, "unknown configuration section"),
    ({"powershell": {"min_indicators": 0}}, "min_indicators must be a positive integer"),
    ({"powershell": {"min_indicators": 9}}, "could never fire"),
    ({"powershell": {"enabled_indicators": ["encoded_command"], "min_indicators": 2}},
     "could never fire"),
    ({"powershell": {"enabled_indicators": ["telepathy"]}}, "unknown indicator"),
    ({"powershell": {"enabled_indicators": []}}, "must not be empty"),
    ({"powershell": {"enabled_indicators": "encoded_command"}}, "list of strings"),
    ({"powershell": {"download_patterns": ["("]}}, "invalid regular expression"),
    ({"powershell": {"invoke_expression_patterns": [""]}}, "non-empty strings"),
    ({"powershell": {"unusual_parents": [5]}}, "non-empty strings"),
    ({"powershell": {"correlation_window_seconds": 0}}, "correlation_window_seconds"),
    ({"powershell": {"ip_policy": {"external_classes": ["invalid"]}}}, "never treated"),
    ({"powershell": {"ip_policy": {"external_classes": ["lan"]}}}, "unknown IP class"),
    ({"powershell": {"ip_policy": {"other": 1}}}, "only 'external_classes'"),
    ({"account_creation": {"privileged_groups": []}}, "must not be empty"),
    ({"account_creation": {"min_context_indicators": 3}}, "at most 2"),
    ({"account_creation": {"min_context_indicators": -1}}, "integer >= 0"),
    ({"account_creation": {"max_ancestry_depth": 0}}, "max_ancestry_depth"),
    ({"account_creation": {"creation_command_patterns": ["[a-"]}}, "invalid regular expression"),
    ({"account_creation": {"require_privileged_target": 1}}, "true or false"),
]


class TestInvalidConfiguration:
    @pytest.mark.parametrize("data, message", INVALID, ids=[str(d)[:60] for d, _ in INVALID])
    def test_invalid_settings_fail_loudly(self, data, message):
        with pytest.raises(ValueError, match=message):
            DetectionConfig.from_dict(data)

    @pytest.mark.parametrize("data", [[], "text", 5, None])
    def test_top_level_must_be_an_object(self, data):
        with pytest.raises(ValueError, match="JSON object"):
            DetectionConfig.from_dict(data)

    def test_direct_construction_is_validated_too(self):
        with pytest.raises(ValueError):
            BruteForceConfig(threshold=0)
        with pytest.raises(ValueError):
            DetectionConfig(brute_force="not a config")

    def test_unknown_option_message_lists_valid_options(self):
        with pytest.raises(ValueError, match="valid options: .*threshold"):
            DetectionConfig.from_dict({"brute_force": {"treshold": 3}})
