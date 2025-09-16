# -*- coding: utf-8 -*-

import ast

import pytest

import sphinxlinter


def parse_content(data):
    return ast.parse(data).body[0]


def test_DOC001():
    content = '''
def foo():
    """
    Title.

    :foo:
    :bar:
    """

    pass
'''
    expected = (
        (2, "DOC001", "Unknown docstring section ({!r})", ("foo",)),
        (2, "DOC001", "Unknown docstring section ({!r})", ("bar",)),
    )
    result = tuple(sphinxlinter.checker(parse_content(content)))
    assert result == expected


@pytest.mark.parametrize("section, value", [
    # param
    ("param", ":param a",),  # missing separator ":" at the end
    ("param", ":param int a",),  # missing separator ":" at the end when type is given
    ("param", ":param:",),  # missing parameter name without description and type
    ("param", ":param: description",),  # missing parameter name without type
    ("param", ":param  : description",),  # missing parameter name (only spaces) without type
    # type
    ("type", ":type",),  # missing separator ":"
    ("type", ":type:",),  # missing separator name and type
    ("type", ":type:int",),  # missing parameter name
    ("type", ":type :int",),  # missing parameter name (only spaces)
    ("type", ":type a:",),  # missing type
    ("type", ":type a: ",),  # missing type (only spaces)
    # return
    ("return", ":return",),  # missing separator ":" and description
    ("return", ":return:",),  # missing description
    ("return", ":return: ",),  # missing description (only spaces)
    # rtype
    ("rtype", ":rtype",),  # missing separator ":" and type
    ("rtype", ":rtype:",),  # missing type
    ("rtype", ":rtype: ",),  # missing type (only spaces)
    # raises
    ("raises", ":raises",),  # missing separator ":" and exception
    ("raises", ":raises:",),  # missing exception
    ("raises", ":raises: ",),  # missing exception (only spaces)
])
def test_DOC002(section, value):
    content = f'''
def foo(a):
    """
    Title.

    {value}
    """
    
    return a
'''
    expected = (
        (2, "DOC002", "Malformed section ({!r})", (section,)),
    )
    result = tuple(sphinxlinter.checker(parse_content(content)))
    assert result == expected


def test_DOC003():
    content = '''
def foo():
    """
    Title.
    """
    pass
'''
    expected = (
        (2, "DOC003", "Missing blank line after docstring", tuple()),
    )
    result = tuple(sphinxlinter.checker(parse_content(content)))
    assert result == expected


def test_DOC101():
    content = '''
def foo():
    """
    Title.

    :param str a:
    """

    pass
'''
    expected = (
        (2, "DOC101", "Parameter documented but not in signature ({!r})", ("a",)),
    )
    result = tuple(sphinxlinter.checker(parse_content(content)))
    assert result == expected


def test_DOC102():
    content = '''
def foo(a):
    """
    Title.

    :param list[str, a: description
    """

    pass
'''
    expected = (
        ((2, 'DOC102', 'Invalid parameter type syntax ({!r})', ('list[str,',)),)
    )
    result = tuple(sphinxlinter.checker(parse_content(content)))
    assert result == expected


def test_DOC103():
    content = '''
def foo(a:int):
    """
    Title.
    :param int a: description
    """ 
    
    pass
'''
    expected = (
        ((2, 'DOC103', 'Parameter type already in signature ({!r})', ('int',)),)
    )
    result = tuple(sphinxlinter.checker(parse_content(content)))
    assert result == expected


def test_DOC104():
    content = '''
def foo(a:int):
    """
    Title.
    :param str a: description
    """ 

    pass
'''
    expected = (
        (
            2,
            'DOC104',
            'Parameter type mismatch with hint ({!r} != {!r})',
            ('str', 'int'),
        ),
    )
    result = tuple(sphinxlinter.checker(parse_content(content)))
    assert result == expected


@pytest.mark.parametrize("repeated", [":type a: int", ":param int a:"])
def test_DOC105(repeated):
    content = f'''
def foo(a):
    """
    Title.
    :param int a: description
    {repeated}
    """ 

    pass
'''
    expected = (
        (2, 'DOC105', 'Duplicated parameter ({!r})', ('a',)),
    )
    result = tuple(sphinxlinter.checker(parse_content(content)))
    assert result == expected
