# -*- coding: utf-8 -*-

import ast
import inspect

import pytest

import sphinxlinter


def parse_function(function):
    return ast.parse(inspect.getsource(function)).body[0]


def function_only_docstring_single_line():
    """This is a docstring."""


def function_only_docstring_empty():
    """ """


def function_only_docstring_multiline():
    """
    This is a docstring.
    It has multiple lines.
    """


def function_ellipsis():
    ...


def function_ellipsis_with_docstring():
    """This is a docstring."""

    ...


def function_ellipsis_not_single():
    a = 1  # noqa
    ...


def function_pass():
    pass


def function_pass_with_docstring():
    """
    This is a docstring."""

    pass


def function_pass_not_single():
    a = 1  # noqa
    pass


def function_NotImplementedError():
    raise NotImplementedError


def function_NotImplementedError_with_docstring():
    """This is a docstring."""

    raise NotImplementedError


def function_NotImplementedError_call():
    raise NotImplementedError("message")


def function_NotImplementedError_call_with_docstring():
    """This is a docstring."""

    raise NotImplementedError("message")


def function_NotImplementedError_call_not_single():
    a = 1  # noqa
    raise NotImplementedError("message")


def function_ValueError():
    raise ValueError


def function_NotImplementedError_cond(x):
    if x:
        raise ValueError
    else:
        raise NotImplementedError


@pytest.mark.parametrize(
    "function, expected",
    [
        (function_only_docstring_single_line, True),
        (function_only_docstring_empty, True),
        (function_only_docstring_multiline, True),
        (function_ellipsis, True),
        (function_ellipsis_with_docstring, True),
        (function_ellipsis_not_single, False),
        (function_pass, True),
        (function_pass_not_single, False),
        (function_pass_with_docstring, True),
        (function_NotImplementedError, True),
        (function_NotImplementedError_with_docstring, True),
        (function_NotImplementedError_call, True),
        (function_NotImplementedError_call_with_docstring, True),
        (function_NotImplementedError_call_not_single, False),
        (function_ValueError, False),
        (function_NotImplementedError_cond, False),
    ],
)
def test_checker_none(function, expected):
    root = parse_function(function)
    rawdocs = ast.get_docstring(root, clean=False)
    result = sphinxlinter.is_not_implemented(root, rawdocs=rawdocs)
    assert result == expected
