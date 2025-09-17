# -*- coding: utf-8 -*-

import ast
import inspect

import pytest

import sphinxlinter


def parse_function(function):
    return ast.parse(inspect.getsource(function)).body[0]


def function_only_docstring_single_line():  # pragma: no cover
    """This is a docstring."""


def function_only_docstring_empty():  # pragma: no cover
    """ """  # noqa: D419


def function_only_docstring_multiline():  # pragma: no cover
    """
    This is a docstring.
    It has multiple lines.
    """


def function_ellipsis():  # pragma: no cover
    ...


def function_ellipsis_with_docstring():  # pragma: no cover
    """This is a docstring."""

    ...


def function_ellipsis_not_single():  # pragma: no cover
    tuple()  # noqa: B018
    ...


def function_pass():  # pragma: no cover
    pass


def function_pass_with_docstring():  # pragma: no cover
    """This is a docstring."""

    pass


def function_pass_not_single():  # pragma: no cover
    tuple()  # noqa: B018
    pass


def function_NotImplementedError():  # pragma: no cover
    raise NotImplementedError


def function_NotImplementedError_with_docstring():  # pragma: no cover
    """This is a docstring."""

    raise NotImplementedError


def function_NotImplementedError_call():  # pragma: no cover
    raise NotImplementedError("message")


def function_NotImplementedError_call_with_docstring():  # pragma: no cover
    """This is a docstring."""

    raise NotImplementedError("message")


def function_NotImplementedError_call_not_single():  # pragma: no cover
    tuple()  # noqa: B018
    raise NotImplementedError("message")


def function_ValueError():  # pragma: no cover
    raise ValueError


def function_NotImplementedError_cond(x):  # pragma: no cover
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
