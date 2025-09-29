# -*- coding: utf-8 -*-

import ast
import inspect

import pytest

import sphinxlinter


def parse_function(function):
    root = ast.parse(inspect.getsource(function))
    return root.body[0]


def function_no_return_no_yield():  # pragma: no cover

    def foo():
        return None

    def bar():
        yield None

    def zas():
        yield from None

    pass


def function_return():  # pragma: no cover

    def foo():
        pass

    def bar():
        pass

    def zas():
        pass

    async def nested():
        pass

    a = dict()
    try:
        a["foo"]
    except KeyError:
        return None


def function_yield_from():  # pragma: no cover
    a = dict()
    try:
        a["foo"]
    except KeyError:
        yield from ""


def function_yield():  # pragma: no cover
    a = dict()
    try:
        a["foo"]
    except KeyError:
        yield None


async def async_none():  # pragma: no cover
    def foo():
        yield from ""

    def bar():
        yield None

    def zas():
        return None

    async def nested():
        pass

    pass


async def async_yield():  # pragma: no cover
    def foo():
        pass

    def bar():
        pass

    def zas():
        pass

    async def nested():
        pass

    yield None


def returns_gen_expr():  # pragma: no cover
    yield from (i for i in range(1))  # noqa: C416, RUF100


def returns_any():  # pragma: no cover
    return [i for i in range(1)]  # noqa: C416, RUF100


@pytest.mark.parametrize(
    "function, expected",
    (
        (function_no_return_no_yield, set()),
        (function_return, {'Any'}),
        (function_yield, {'Generator'}),
        (function_yield_from, {'Generator'}),
        (async_none, set()),
        (async_yield, {'AsyncGenerator'}),
        (returns_gen_expr, {'Generator'}),
        (returns_any, {'Any'}),
    ),
)
def test_checker_none(function, expected):
    root = parse_function(function)
    result = sphinxlinter.get_func_return_types(root)
    assert result == expected
