"""Policy: ``processes.command_line`` is required but may be null.

Everything else that is required must stay non-null. These tests pin both
halves of that rule, and check that the contract document, the machine-readable
constants and the validator agree.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from helpers import SAMPLE_DIR, edit, error_codes, warning_codes

from security.models.schemas import (
    NULLABLE_REQUIRED_FIELDS,
    REQUIRED_RECORD_FIELDS,
    EvidenceSource,
)
from security.validation import validate_case

CONTRACT = Path(__file__).resolve().parents[1] / "docs" / "EVIDENCE_CONTRACT.md"


class TestCommandLinePolicy:
    def test_non_null_command_line_is_valid(self):
        assert validate_case(SAMPLE_DIR).valid

    def test_null_command_line_is_valid_and_clean(self, case):
        edit(case, "processes.json",
             lambda d: d["records"][0].update(command_line=None))
        result = validate_case(case)
        assert result.valid
        assert result.errors == [] and result.warnings == []

    def test_null_command_line_on_every_record_is_valid(self, case):
        def mutate(d):
            for record in d["records"]:
                record["command_line"] = None
        edit(case, "processes.json", mutate)
        assert validate_case(case).valid

    def test_mixed_null_and_non_null_is_valid(self, case):
        def mutate(d):
            d["records"][0]["command_line"] = None   # others stay non-null
        edit(case, "processes.json", mutate)
        assert validate_case(case).valid

    def test_key_is_still_required(self, case):
        edit(case, "processes.json", lambda d: d["records"][0].pop("command_line"))
        result = validate_case(case)
        assert error_codes(result) == {"FIELD_MISSING"}
        assert result.errors[0].field == "command_line"
        assert result.errors[0].record_id == "PROC-0001"

    @pytest.mark.parametrize("value", ["", "   "])
    def test_empty_string_is_not_a_substitute_for_null(self, case, value):
        edit(case, "processes.json",
             lambda d: d["records"][0].update(command_line=value))
        result = validate_case(case)
        assert error_codes(result) == {"FIELD_EMPTY"}
        assert warning_codes(result) == set()

    @pytest.mark.parametrize("value", [123, True, ["a"], {"a": 1}])
    def test_wrong_type_is_still_rejected(self, case, value):
        edit(case, "processes.json",
             lambda d: d["records"][0].update(command_line=value))
        assert error_codes(validate_case(case)) == {"FIELD_TYPE"}


OTHER_REQUIRED = [
    (source, name)
    for source in EvidenceSource
    for name in REQUIRED_RECORD_FIELDS[source]
    if name not in NULLABLE_REQUIRED_FIELDS.get(source, ())
]


class TestNoOtherRequiredFieldMayBeNull:
    @pytest.mark.parametrize("source, field", OTHER_REQUIRED,
                             ids=[f"{s.value}.{f}" for s, f in OTHER_REQUIRED])
    def test_null_is_rejected(self, case, source, field):
        edit(case, f"{source.value}.json",
             lambda d: d["records"][0].update({field: None}))
        result = validate_case(case)
        assert error_codes(result) == {"FIELD_NULL"}
        assert result.errors[0].field == field


class TestPolicyIsConsistentEverywhere:
    def test_exactly_one_nullable_required_field(self):
        assert NULLABLE_REQUIRED_FIELDS == {
            EvidenceSource.PROCESSES: ("command_line",)}

    def test_nullable_fields_are_required_fields(self):
        for source, names in NULLABLE_REQUIRED_FIELDS.items():
            assert set(names) <= set(REQUIRED_RECORD_FIELDS[source])

    def test_contract_documents_the_rule(self):
        text = CONTRACT.read_text(encoding="utf-8")
        row = next(line for line in text.splitlines()
                   if line.startswith("| command_line"))
        assert "null" in row and "R" in row
        missing_values = next(line for line in text.splitlines()
                              if line.startswith("| Missing values"))
        assert "command_line" in missing_values
        assert re.search(r"2026-10-09.*command_line", text)
