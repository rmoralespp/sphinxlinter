# -*- coding: utf-8 -*-

import keyword

import pytest

import sphinxlinter

ok_type_hints_kw = keyword.softkwlist + ["False", "None", "True"]
ko_type_hints_kw = [kw for kw in (keyword.kwlist + keyword.softkwlist) if kw not in ok_type_hints_kw]


class TestViolations:

    @pytest.mark.parametrize("hint, expected", [
        ("", False),
        ("int", True),
        ("str", True),
        ("list[int]", True),
        ("dict[str, Any]", True),
        # valid syntax, but not a type hint
        # --------------------------------------------------------------------
        ("2 + 2", True),
        ("NotFound", True),
        ("...", True),
        ("foo()", True),
        # invalid syntax
        # --------------------------------------------------------------------
        ("list[]", False),
        ("list[int", False),
        ("dict[int; Any]", False),
        # --------------------------------------------------------------------
        # keywords in type hints
        # --------------------------------------------------------------------
        *tuple(zip(ok_type_hints_kw, (True,) * len(ok_type_hints_kw))),
        *tuple(zip(ko_type_hints_kw, (False,) * len(ko_type_hints_kw))),
    ])
    def test_is_valid_type_hint(self, hint, expected):
        result = sphinxlinter.Violations.is_valid_type_hint(hint)
        assert result == expected
