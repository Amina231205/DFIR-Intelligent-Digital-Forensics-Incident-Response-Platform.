"""Phase 5 tests: IP classification and the external-address policy."""

from __future__ import annotations

import dataclasses

import pytest

from security.detection import IpClass, IpPolicy, classify_ip

CASES = {
    IpClass.PUBLIC: ["8.8.8.8", "1.1.1.1", "172.32.0.1", "172.15.255.255", "11.0.0.1",
                     "2606:4700::1111", "::ffff:8.8.8.8"],
    IpClass.PRIVATE: ["10.0.0.1", "10.255.255.255", "172.16.0.1", "172.31.255.255",
                      "192.168.0.1", "192.168.255.254", "fc00::1", "fd12:3456::1",
                      "::ffff:10.1.2.3"],
    IpClass.LOOPBACK: ["127.0.0.1", "127.255.255.254", "::1", "::ffff:127.0.0.1"],
    IpClass.LINK_LOCAL: ["169.254.1.1", "169.254.255.254", "fe80::1"],
    IpClass.MULTICAST: ["224.0.0.1", "239.255.255.255", "ff02::1"],
    IpClass.UNSPECIFIED: ["0.0.0.0", "::"],
    IpClass.DOCUMENTATION: ["192.0.2.1", "198.51.100.23", "203.0.113.77", "2001:db8::1"],
    IpClass.RESERVED: ["100.64.0.1", "255.255.255.255", "240.0.0.1", "198.18.0.1"],
    IpClass.MISSING: [None, "", "   ", "-", " - "],
    IpClass.INVALID: ["abc", "999.1.1.1", "1.2.3", "10.0.0", "010.0.0.1", "1.2.3.4.5",
                      "10.0.0.1/8", "::gggg", 12345, 1.5, b"1.2.3.4", ["1.1.1.1"]],
}
PAIRS = [(value, ip_class) for ip_class, values in CASES.items() for value in values]


class TestClassification:
    @pytest.mark.parametrize("value, expected", PAIRS, ids=[repr(v) for v, _ in PAIRS])
    def test_classification(self, value, expected):
        assert classify_ip(value) is expected

    def test_surrounding_whitespace_is_ignored(self):
        assert classify_ip(" 8.8.8.8 ") is IpClass.PUBLIC

    def test_rfc1918_boundaries(self):
        assert classify_ip("172.15.255.255") is IpClass.PUBLIC
        assert classify_ip("172.16.0.0") is IpClass.PRIVATE
        assert classify_ip("172.31.255.255") is IpClass.PRIVATE
        assert classify_ip("172.32.0.0") is IpClass.PUBLIC

    def test_documentation_ranges_are_not_called_private(self):
        # Python's ipaddress says is_private=True for these; our policy does not.
        assert classify_ip("203.0.113.77") is IpClass.DOCUMENTATION

    def test_multicast_is_not_called_public(self):
        # Python's ipaddress says is_global=True for 224.0.0.1; our policy does not.
        assert classify_ip("224.0.0.1") is IpClass.MULTICAST

    def test_missing_is_distinct_from_invalid(self):
        assert classify_ip("-") is IpClass.MISSING
        assert classify_ip("not-an-ip") is IpClass.INVALID

    def test_every_class_is_covered_by_the_table(self):
        assert set(CASES) == set(IpClass)


class TestPolicy:
    EXTERNAL = [IpClass.PUBLIC]            # default: only genuinely public addresses

    @pytest.mark.parametrize("ip_class, values", CASES.items(), ids=lambda x: str(x)[:18])
    def test_default_policy(self, ip_class, values):
        expected = (None if ip_class in (IpClass.MISSING, IpClass.INVALID)
                    else ip_class in self.EXTERNAL)
        assert {IpPolicy().is_external(v) for v in values} == {expected}

    def test_default_external_classes(self):
        assert IpPolicy().external_classes == frozenset(self.EXTERNAL)

    def test_documentation_ranges_are_never_external_by_default(self):
        for value in CASES[IpClass.DOCUMENTATION]:
            assert classify_ip(value) is IpClass.DOCUMENTATION       # still not "public"
            assert IpPolicy().is_external(value) is False
        assert IpClass.DOCUMENTATION not in IpPolicy().external_classes

    def test_documentation_ranges_can_be_opted_in_explicitly(self):
        for policy in (IpPolicy.from_classes([IpClass.PUBLIC, IpClass.DOCUMENTATION]),
                       IpPolicy.from_classes(["public", "documentation"]),
                       IpPolicy.synthetic_demo()):
            assert policy.is_external("8.8.8.8") is True
            assert policy.is_external("203.0.113.77") is True
            assert policy.is_external("10.0.0.1") is False

    def test_synthetic_demo_policy_is_distinct_from_the_default(self):
        assert IpPolicy.synthetic_demo() != IpPolicy()
        assert IpPolicy.synthetic_demo().external_classes == frozenset(
            {IpClass.PUBLIC, IpClass.DOCUMENTATION})

    def test_private_can_be_included(self):
        policy = IpPolicy.from_classes(["public", "private"])
        assert policy.is_external("10.0.0.1") is True
        assert policy.is_external("127.0.0.1") is False

    def test_unknown_addresses_are_never_external_or_internal(self):
        policy = IpPolicy.from_classes(list(IpClass)[:8])    # every classifiable class
        assert policy.is_external("abc") is None
        assert policy.is_external(None) is None

    @pytest.mark.parametrize("bad", [["missing"], ["invalid"], ["nonsense"], [42]])
    def test_invalid_policies_are_rejected(self, bad):
        with pytest.raises(ValueError):
            IpPolicy.from_classes(bad)

    def test_policy_is_immutable(self):
        with pytest.raises(dataclasses.FrozenInstanceError):
            IpPolicy().external_classes = frozenset()
