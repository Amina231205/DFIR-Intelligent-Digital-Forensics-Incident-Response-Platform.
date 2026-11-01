"""Phase 7 tests: the condition language used by mapping rules."""

from __future__ import annotations

import pytest
from mitre_helpers import acct_context, bf_context, finding, indicator, ioc

from security.mitre.conditions import (
    CHECKS,
    Subject,
    collect_event_ids,
    evaluate,
    render_rationale,
    select_iocs,
    validate_condition,
    validate_evidence,
    validate_ioc_spec,
    validate_template,
)


def subject(f=None, iocs=None) -> Subject:
    return Subject(f or finding(), iocs)


def check(name: str, **params) -> dict:
    return {"check": name, **params}


class TestLeafChecks:
    def test_indicator_present(self):
        f = finding(
            indicators=(
                indicator("encoded_command"),
                indicator("privileged_target", basis="users_snapshot"),
            )
        )
        assert (
            evaluate(check("indicator_present", indicator="encoded_command"), subject(f))[0] is True
        )
        assert (
            evaluate(check("indicator_present", indicator="hidden_window"), subject(f))[0] is False
        )
        assert (
            evaluate(
                check(
                    "indicator_present",
                    indicator="privileged_target",
                    where={"basis": "users_snapshot"},
                ),
                subject(f),
            )[0]
            is True
        )
        assert (
            evaluate(
                check(
                    "indicator_present",
                    indicator="privileged_target",
                    where={"basis": "group_membership_event"},
                ),
                subject(f),
            )[0]
            is False
        )

    def test_indicator_in_decoded_text(self):
        plain = finding(indicators=(indicator("download_cradle"),))
        decoded = finding(
            indicators=(indicator("download_cradle", field="command_line (decoded)"),)
        )
        node = check("indicator_in_decoded_text")
        assert evaluate(node, subject(plain))[0] is False
        assert evaluate(node, subject(decoded))[0] is True
        assert (
            evaluate(
                check("indicator_in_decoded_text", indicator="hidden_window"), subject(decoded)
            )[0]
            is False
        )

    @pytest.mark.parametrize(
        "context, expected",
        [({"a": {"b": 1}}, True), ({"a": {"b": 2}}, False), ({"a": {}}, None), ({}, None)],
    )
    def test_context_equals_is_unknown_when_missing(self, context, expected):
        f = finding(context=context)
        assert evaluate(check("context_equals", path="a.b", value=1), subject(f))[0] is expected

    @pytest.mark.parametrize(
        "value, expected",
        [("x", True), (0, True), (False, True), (None, False), ("", False), ("  ", False)],
    )
    def test_context_not_null_and_missing_are_opposites(self, value, expected):
        f = finding(context={"k": value})
        assert evaluate(check("context_not_null", path="k"), subject(f))[0] is expected
        assert evaluate(check("context_missing", path="k"), subject(f))[0] is (not expected)

    def test_absent_path_counts_as_missing(self):
        f = finding(context={})
        assert evaluate(check("context_not_null", path="k"), subject(f))[0] is False
        assert evaluate(check("context_missing", path="k"), subject(f))[0] is True

    @pytest.mark.parametrize(
        "value, expected", [([1], True), ([], False), ("text", False), (None, False)]
    )
    def test_context_list_nonempty(self, value, expected):
        f = finding(context={"k": value})
        assert evaluate(check("context_list_nonempty", path="k"), subject(f))[0] is expected

    def test_context_list_nonempty_is_unknown_when_absent(self):
        assert (
            evaluate(check("context_list_nonempty", path="k"), subject(finding(context={})))[0]
            is None
        )

    @pytest.mark.parametrize(
        "value, expected", [(5, True), (4.9, False), (6, True), ("5", False), (True, False)]
    )
    def test_context_number_at_least(self, value, expected):
        f = finding(context={"n": value})
        assert (
            evaluate(check("context_number_at_least", path="n", value=5), subject(f))[0] is expected
        )

    def test_context_at_least_multiple_boundaries(self):
        node = check("context_at_least_multiple", path="failure_count", of="threshold", factor=2)
        assert evaluate(node, subject(finding(context=bf_context(10, 5))))[0] is True
        assert evaluate(node, subject(finding(context=bf_context(9, 5))))[0] is False
        assert evaluate(node, subject(finding(context={"failure_count": 9})))[0] is None

    @pytest.mark.parametrize(
        "reasons, expected",
        [
            ({"wrong password": 4, "other": 1}, True),  # exactly 80%
            ({"wrong password": 7, "other": 3}, False),  # 70%
            ({"other": 5}, False),
            ({}, False),
            ("not a dict", False),
            (None, None),
        ],
    )
    def test_context_share_at_least(self, reasons, expected):
        f = finding(
            context=(
                bf_context(5, reasons=reasons)
                if reasons is not None
                else bf_context(5, reasons=None)
            )
        )
        node = check(
            "context_share_at_least", path="failure_reasons", key="wrong password", min_share=0.8
        )
        assert evaluate(node, subject(f))[0] is expected

    @pytest.mark.parametrize(
        "domain, expected",
        [("PC-1", True), ("pc-1", True), ("OTHER", False), (None, None), ("", None)],
    )
    def test_context_equals_finding_field(self, domain, expected):
        f = finding(context=acct_context(target_domain=domain))
        node = check(
            "context_equals_finding_field", path="target_domain", field="device", casefold=True
        )
        assert evaluate(node, subject(f))[0] is expected

    def test_casefold_is_optional(self):
        f = finding(context=acct_context(target_domain="pc-1"))
        assert (
            evaluate(
                check("context_equals_finding_field", path="target_domain", field="device"),
                subject(f),
            )[0]
            is False
        )

    def test_ioc_related(self):
        iocs = [
            ioc("IOC-001", "url", "http://a.example.com/x", ("F-001",)),
            ioc("IOC-002", "hash", "a1" * 32, ("F-001",), files=("files.json",)),
            ioc("IOC-003", "username", "svc", ("F-001",), roles=["account that was created"]),
        ]
        s = subject(iocs=iocs)
        assert evaluate(check("ioc_related", type="url"), s)[0] is True
        assert evaluate(check("ioc_related", type="ip"), s)[0] is False
        assert evaluate(check("ioc_related", type="hash", evidence_file="files.json"), s)[0] is True
        assert (
            evaluate(check("ioc_related", type="hash", evidence_file="processes.json"), s)[0]
            is False
        )
        assert (
            evaluate(check("ioc_related", type="username", role_contains="was created"), s)[0]
            is True
        )
        assert (
            evaluate(check("ioc_related", type="username", role_contains="added to group"), s)[0]
            is False
        )

    def test_ioc_related_is_unknown_without_ioc_input(self):
        value, why = evaluate(check("ioc_related", type="url"), subject(iocs=None))
        assert value is None and "IOC input was not provided" in why

    def test_every_check_has_a_function_and_parameters(self):
        for name, (required, optional, function) in CHECKS.items():
            assert callable(function) and not (required & optional), name


class TestCombinators:
    T, F, N = (
        check("context_equals", path="k", value=1),
        check("context_equals", path="k", value=2),
        check("context_equals", path="missing", value=1),
    )
    SUBJECT = finding(context={"k": 1})

    @pytest.mark.parametrize(
        "node, expected",
        [
            ({"all": [T, T]}, True),
            ({"all": [T, F]}, False),
            ({"all": [T, N]}, None),
            ({"all": [F, N]}, False),  # a False beats an unknown
            ({"any": [F, F]}, False),
            ({"any": [F, T]}, True),
            ({"any": [F, N]}, None),
            ({"any": [T, N]}, True),  # a True beats an unknown
            ({"not": T}, False),
            ({"not": F}, True),
            ({"not": N}, None),
            ({"all": [T, {"any": [F, {"not": F}]}]}, True),
        ],
    )
    def test_three_valued_logic(self, node, expected):
        assert evaluate(node, Subject(self.SUBJECT, None))[0] is expected

    def test_explanations_name_the_deciding_conditions(self):
        value, why = evaluate({"all": [self.T, self.F]}, Subject(self.SUBJECT, None))
        assert value is False and "expected 2" in why and "expected 1" not in why
        value, why = evaluate({"all": [self.T, self.T]}, Subject(self.SUBJECT, None))
        assert why == "all conditions met"


class TestEvidenceAndRationale:
    def test_event_ids_from_every_source(self):
        f = finding(
            events=("E-00001", "E-00002", "E-00003"),
            indicators=(
                indicator("encoded_command", "E-00007"),
                indicator("privileged_target", "E-00008", basis="group_membership_event"),
            ),
            context={
                "creation_event_id": "E-00010",
                "creating_evidence": [{"event_id": "E-00011"}, {"event_id": "E-00012", "k": 1}],
                "process": {"process_event_id": "E-00004"},
                "success": "E-00003",
            },
        )
        s = subject(f)

        def collect(*specs):
            return collect_event_ids(list(specs), s)

        assert collect({"events_from": "finding"}) == ["E-00001", "E-00002", "E-00003"]
        assert collect({"events_from": "finding", "except_context": ["success"]}) == [
            "E-00001",
            "E-00002",
        ]
        assert collect({"events_from": "indicator", "indicator": "encoded_command"}) == ["E-00007"]
        assert (
            collect(
                {
                    "events_from": "indicator",
                    "indicator": "privileged_target",
                    "where": {"basis": "users_snapshot"},
                }
            )
            == []
        )
        assert collect({"events_from": "context_value", "path": "creation_event_id"}) == ["E-00010"]
        assert collect({"events_from": "context_value", "path": "nope"}) == []
        assert collect(
            {"events_from": "context_records", "path": "creating_evidence", "key": "event_id"}
        ) == ["E-00011", "E-00012"]
        assert collect(
            {
                "events_from": "context_records",
                "path": "creating_evidence",
                "key": "event_id",
                "where": {"k": 1},
            }
        ) == ["E-00012"]
        assert collect({"events_from": "finding"}, {"events_from": "finding"}) == [
            "E-00001",
            "E-00002",
            "E-00003",
        ]  # unique

    def test_ioc_selection(self):
        iocs = [
            ioc("IOC-001", "ip", "1.1.1.1", ("F-001",)),
            ioc("IOC-002", "username", "a", ("F-001",), roles=["account that was created"]),
            ioc("IOC-003", "username", "b", ("F-001",), roles=["account of a failed logon"]),
        ]
        s = subject(iocs=iocs)
        assert [i.ioc_id for i in select_iocs({"types": ["ip", "username"]}, s)] == [
            "IOC-001",
            "IOC-002",
            "IOC-003",
        ]
        assert [
            i.ioc_id
            for i in select_iocs({"types": ["username"], "role_contains": "was created"}, s)
        ] == ["IOC-002"]
        assert select_iocs({"types": []}, s) == []  # empty types select nothing
        assert select_iocs({"types": ["ip"]}, subject(iocs=None)) == []

    def test_rationale_placeholders(self):
        f = finding(
            indicators=(indicator("b"), indicator("a"), indicator("a")),
            context={**bf_context(6, reasons={"wrong password": 6})},
            user="ahmed",
        )
        text = render_rationale(
            "{finding.finding_id} {finding.user} {ctx.failure_count} {ctx.grouping.source_ip} "
            "{ctx.failure_reasons} {indicators} {ctx.nope} {finding.device}",
            subject(f),
        )
        assert text == "F-001 ahmed 6 198.51.100.23 wrong password=6 a, b unknown PC-1"

    def test_rationale_renders_lists_and_blank_values(self):
        f = finding(context={"items": ["x", "y"], "empty": [], "blank": " "})
        assert (
            render_rationale("{ctx.items}|{ctx.empty}|{ctx.blank}", subject(f))
            == "x, y|none|unknown"
        )

    def test_rationale_never_exposes_object_internals(self):
        f = finding(context={})
        assert render_rationale("{ctx.__class__}", subject(f)) == "unknown"
        with pytest.raises(ValueError, match="unsupported placeholder"):
            validate_template("{finding.__class__}", "rule")


class TestValidation:
    @pytest.mark.parametrize(
        "node, message",
        [
            ("not a dict", "must be an object"),
            ({}, "exactly one of"),
            ({"check": "context_equals", "all": []}, "exactly one of"),
            ({"check": "made_up"}, "unknown check"),
            ({"check": "context_equals", "path": "k"}, "missing parameter"),
            ({"check": "context_equals", "path": "k", "value": 1, "extra": 1}, "unknown parameter"),
            ({"check": "context_not_null", "path": ""}, "non-empty string"),
            ({"check": "context_number_at_least", "path": "k", "value": "5"}, "must be a number"),
            (
                {"check": "context_share_at_least", "path": "k", "key": "x", "min_share": 1.5},
                r"\(0, 1\]",
            ),
            (
                {"check": "context_share_at_least", "path": "k", "key": "x", "min_share": 0},
                r"\(0, 1\]",
            ),
            (
                {"check": "context_equals_finding_field", "path": "k", "field": "context"},
                "'field' must be",
            ),
            (
                {
                    "check": "context_equals_finding_field",
                    "path": "k",
                    "field": "device",
                    "casefold": "yes",
                },
                "true or false",
            ),
            (
                {"check": "indicator_present", "indicator": "x", "where": []},
                "'where' must be an object",
            ),
            ({"all": []}, "non-empty list"),
            ({"any": "x"}, "non-empty list"),
            ({"all": [{"check": "context_not_null", "path": "k"}], "extra": 1}, "nothing else"),
            ({"not": {"check": "made_up"}}, "unknown check"),
            ({"not": {"check": "context_not_null", "path": "k"}, "x": 1}, "only one condition"),
        ],
    )
    def test_invalid_conditions(self, node, message):
        with pytest.raises(ValueError, match=message):
            validate_condition(node, "rule")

    def test_nested_errors_name_their_position(self):
        node = {"all": [{"check": "context_not_null", "path": "k"}, {"any": [{"check": "nope"}]}]}
        with pytest.raises(ValueError, match=r"rule\.all\[1\]\.any\[0\]"):
            validate_condition(node, "rule")

    @pytest.mark.parametrize(
        "specs, message",
        [
            ([], "non-empty list"),
            ("x", "non-empty list"),
            ([{"events_from": "magic"}], "events_from"),
            ([{"events_from": "indicator"}], "missing parameter"),
            ([{"events_from": "finding", "extra": 1}], "unknown parameter"),
            ([{"events_from": "context_records", "path": "p"}], "missing parameter"),
            ([{"events_from": "finding", "except_context": "x"}], "list of context paths"),
            (
                [{"events_from": "indicator", "indicator": "x", "where": "y"}],
                "'where' must be an object",
            ),
        ],
    )
    def test_invalid_evidence_specs(self, specs, message):
        with pytest.raises(ValueError, match=message):
            validate_evidence(specs, "rule")

    @pytest.mark.parametrize(
        "spec, message",
        [
            ("x", "object with a 'types' list"),
            ({}, "'types' list"),
            ({"types": "ip"}, "list of strings"),
            ({"types": [1]}, "list of strings"),
            ({"types": [], "extra": 1}, "unknown ioc option"),
        ],
    )
    def test_invalid_ioc_specs(self, spec, message):
        with pytest.raises(ValueError, match=message):
            validate_ioc_spec(spec, "rule")

    @pytest.mark.parametrize(
        "template, message",
        [
            ("", "non-empty string"),
            (5, "non-empty string"),
            ("{x}", "unsupported placeholder"),
            ("{finding.nope}", "unsupported placeholder"),
            ("{ctx.}", "unsupported placeholder"),
            ("{ctx.a} and { oops", "unbalanced braces"),
            ("text }", "unbalanced braces"),
        ],
    )
    def test_invalid_templates(self, template, message):
        with pytest.raises(ValueError, match=message):
            validate_template(template, "rule")

    def test_valid_templates(self):
        validate_template("{finding.device} {ctx.a.b} {indicators} plain text", "rule")
