# -*- coding: utf-8 -*-

import ast
import keyword
import unittest.mock

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

    def test_validate_summary(self):
        # Test condition when there is no summary at all

        content = '''
def dummy():
    """
    :return: foo
    """

    pass
'''

        parsed = sphinxlinter.parse_docs(ast.parse(content).body[0])
        result = tuple(sphinxlinter.Violations.validate_summary(parsed))
        assert not result

    @pytest.mark.parametrize("value", (None, ""))
    def test_validate_empty_lines(self, value):
        # Test condition when there is no docstring (or empty)
        parsed = sphinxlinter.ParsedDocs(
            summary=None,
            params=list(),
            raises=list(),
            returns=list(),
            invalid=list(),
            rawdocs=value,
            docs=None,
            docs_ini_lineno=None,
            docs_end_lineno=None,
            code_ini_lineno=0,
        )
        result = tuple(sphinxlinter.Violations.validate_empty_lines(parsed))
        assert not result

    @pytest.mark.parametrize(
        "docstring, expected",
        (
            (None, None),
            ("", None),
            (" a\nb \n\n ", " a\nb \n\n "),
            (" a \n:b: \n\n", " a \n"),
        ),
    )
    def test_get_summary(self, docstring, expected):
        result = sphinxlinter.get_summary(docstring)
        assert result == expected

    def test_empty_docstring(self):
        content = '''
def dummy():
    pass
'''
        # Test empty docstring does not return sections
        expected = sphinxlinter.ParsedDocs(
            summary=None,
            params=list(),
            raises=list(),
            returns=list(),
            invalid=list(),
            rawdocs=None,
            docs=None,
            docs_ini_lineno=None,
            docs_end_lineno=None,
            code_ini_lineno=3,
        )
        result = sphinxlinter.parse_docs(ast.parse(content).body[0])
        assert result == expected

    def test_walk_module_syntax_error(self):
        data = object()
        filename = object()
        expected = tuple()
        with unittest.mock.patch("sphinxlinter.ast.parse", side_effect=SyntaxError) as parser:
            result = tuple(sphinxlinter.walk_module(data, filename))

        assert result == expected
        parser.assert_called_once_with(data, filename=filename)

    def test_walk_module(self):
        data = object()
        filename = object()
        guard = object()
        expected = (
            ast.FunctionDef("foo", tuple()),
            ast.AsyncFunctionDef("bar", tuple()),
        )
        walk = (ast.Module(), ast.Return()) + expected
        with (
            unittest.mock.patch("sphinxlinter.ast.parse", return_value=guard) as parser,
            unittest.mock.patch("sphinxlinter.ast.walk", return_value=walk) as walker,
        ):
            result = tuple(sphinxlinter.walk_module(data, filename))

        assert result == expected
        parser.assert_called_once_with(data, filename=filename)
        walker.assert_called_once_with(guard)

    def test_check_node_no_warnings(self):
        filename = object()
        node = object()
        lines = tuple()
        with unittest.mock.patch("sphinxlinter.checker", return_value=lines) as checker:
            result = sphinxlinter.check_node(filename, node)

        checker.assert_called_once_with(node)
        assert result

    def test_check_node_warnings(self):
        filename = "foo"
        node = object()
        lines = (
            (1, "CODE001", "message", tuple()),
            (3, "CODE00X", "bar {}-{}", (True, 5)),
        )
        expected = (
            "foo:1: [CODE001] message",
            "foo:3: [CODE00X] bar True-5",
        )
        with (
            unittest.mock.patch("sphinxlinter.checker", return_value=lines) as checker,
            unittest.mock.patch("sphinxlinter.print") as printer,
        ):
            result = sphinxlinter.check_node(filename, node)

        printer.assert_has_calls(tuple(map(unittest.mock.call, expected)))
        checker.assert_called_once_with(node)
        assert not result
