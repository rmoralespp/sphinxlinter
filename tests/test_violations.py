# -*- coding: utf-8 -*-

import ast

import pytest

import sphinxlinter


def parse_content(data):
    return ast.parse(data).body[0]


@pytest.fixture(scope='module')
def violations():
    return sphinxlinter.Violations()


def test_empty(violations):
    content = '''
def foo():
    """"""

    pass
'''
    result = tuple(sphinxlinter.checker(parse_content(content), violations))
    assert not result


def test_trailing_line_ok(violations):
    """Checks empty finditer:span."""

    content = '''
def foo():
    """Foo.\n"""

    pass
'''
    result = tuple(sphinxlinter.checker(parse_content(content), violations))
    assert not result


def test_DOC001_function(violations):
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
        (3, "DOC001", "Invalid docstring section ({!r})", ("foo",)),
        (3, "DOC001", "Invalid docstring section ({!r})", ("bar",)),
    )
    result = tuple(sphinxlinter.checker(parse_content(content), violations))
    assert result == expected


def test_DOC001_function_duplicated(violations):
    content = '''
def foo():
    """
    Title.

    :foo:
    :foo:
    """

    pass
'''
    expected = (
        (3, "DOC001", "Invalid docstring section ({!r})", ("foo",)),
    )
    result = tuple(sphinxlinter.checker(parse_content(content), violations))
    assert result == expected


def test_DOC001_class(violations):
    content = '''
class Foo:
    """
    Title.

    :param str a: description
    :param int b: description
    :raises ValueError: description
    :return: description
    :rtype: int
    """

'''
    expected = (
        (3, 'DOC001', 'Invalid docstring section ({!r})', ('param',)),  # twice, but only once reported
        (3, 'DOC001', 'Invalid docstring section ({!r})', ('raises',)),
        (3, 'DOC001', 'Invalid docstring section ({!r})', ('return',)),
        (3, 'DOC001', 'Invalid docstring section ({!r})', ('rtype',)),
    )
    result = tuple(sphinxlinter.checker(parse_content(content), violations))
    assert result == expected


@pytest.mark.parametrize("section", tuple(sphinxlinter.ignore_set))
def test_DOC001_ignored(section, violations):
    content = f'''
def foo():
    """
    Title.

    :{section}:
    """

    pass
'''
    result = tuple(sphinxlinter.checker(parse_content(content), violations))
    assert not result


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
    ("return", ":return value: description",),  # invalid return name (should be empty)
    # rtype
    ("rtype", ":rtype",),  # missing separator ":" and type
    ("rtype", ":rtype:",),  # missing type
    ("rtype", ":rtype: ",),  # missing type (only spaces)
    ("rtype", ":rtype value: description",),  # invalid return name (should be empty)
    # raises
    ("raises", ":raises",),  # missing separator ":" and exception
    ("raises", ":raises:",),  # missing exception
    ("raises", ":raises: ",),  # missing exception (only spaces)
])
def test_DOC002(section, value, violations):
    content = f'''
def foo(a):
    """
    Title.

    {value}
    """

    return a
'''
    expected = (
        (3, "DOC002", "Malformed section ({!r})", (section,)),
    )
    result = tuple(sphinxlinter.checker(parse_content(content), violations))
    assert result == expected


def test_DOC003(violations):
    content = '''
def foo():
    """
    Title.
    """
    pass
'''
    expected = (
        (3, "DOC003", "Missing blank line after docstring", tuple()),
    )
    result = tuple(sphinxlinter.checker(parse_content(content), violations))
    assert result == expected


def test_DOC004(violations):
    content = '''
def foo(a):
    """
    Title.
    :param str a: description
    """

    pass
'''
    expected = (
        (3, "DOC004", "Missing blank line between summary and sections", ()),
    )
    result = tuple(sphinxlinter.checker(parse_content(content), violations))
    assert result == expected


def test_DOC005(violations):
    content = '''
def foo(a):
    """
    Title.


    :param str a: description
    """

    pass
'''

    expected = (
        (3, "DOC005", "Too many consecutive empty lines", ()),
    )
    result = tuple(sphinxlinter.checker(parse_content(content), violations))
    assert result == expected


def test_DOC006(violations):
    content = '''
def foo(a):
    """
    Title.

    :param str a: description

    """

    pass
'''

    expected = (
        (3, "DOC006", "Trailing empty lines", ()),
    )
    result = tuple(sphinxlinter.checker(parse_content(content), violations))
    assert result == expected


def test_DOC006_empty_line(violations):
    content = '''
def foo():
    """
    """

    pass
'''
    expected = (
        (3, "DOC006", "Trailing empty lines", ()),
    )
    result = tuple(sphinxlinter.checker(parse_content(content), violations))
    assert result == expected


@pytest.mark.parametrize("docs", ["Title", "\nTitle"])
def test_DOC008_oneline_docstring(violations, docs):
    content = f'''
def foo(a):
    """{docs}"""
'''

    expected = (
        (3, "DOC008", "One-line docstring should end with a period", ()),
    )
    result = tuple(sphinxlinter.checker(parse_content(content), violations))
    assert result == expected


@pytest.mark.parametrize("docs", [
    "A multi-line\ndocstring",
    "A one-line title\n\n:param str a:",
    "A one-line title\n\n:var: Ignored section",
])
def test_DOC008_multiline_docstring_no_raise(violations, docs):
    content = f'''
def foo(a):
    """
    {docs}
    """
'''

    expected = ()
    result = tuple(sphinxlinter.checker(parse_content(content), violations))
    assert result == expected


@pytest.mark.parametrize("docs", [
    '""""\nTitle."""',  # four quotes at the start
    '"""" \nTitle."""',  # four quotes at the start with space
])
def test_DOC009(violations, docs):
    content = f'''
def foo():
    {docs}

    pass
'''

    expected = ((3, 'DOC009', 'Docstring must not use more than 3 double quotes', ()),)

    result = tuple(sphinxlinter.checker(parse_content(content), violations))
    assert result == expected


@pytest.mark.parametrize("docs", [
    '""""Title."""',  # four quotes at the start
    '"""" foo\nTitle."""',  # four quotes at the start with space because exists more words
])
def test_DOC009_no_raise(violations, docs):
    content = f'''
def foo():
    {docs}

    pass
'''
    expected = ()
    result = tuple(sphinxlinter.checker(parse_content(content), violations))
    assert result == expected


def test_DOC101(violations):
    content = '''
def foo():
    """
    Title.

    :param str a:
    """

    pass
'''
    expected = (
        (3, "DOC101", "Parameter documented but not in signature ({!r})", ("a",)),
    )
    result = tuple(sphinxlinter.checker(parse_content(content), violations))
    assert result == expected


def test_DOC102(violations):
    content = '''
def foo(a):
    """
    Title.

    :param list[str, a: description
    """

    pass
'''
    expected = (
        ((3, "DOC102", "Invalid parameter type syntax ({!r})", ("list[str,",)),)
    )
    result = tuple(sphinxlinter.checker(parse_content(content), violations))
    assert result == expected


def test_DOC103(violations):
    content = '''
def foo(a:int):
    """
    Title.

    :param int a: description
    """

    pass
'''
    expected = (
        ((3, "DOC103", "Parameter type already in signature ({!r})", ("int",)),)
    )
    result = tuple(sphinxlinter.checker(parse_content(content), violations))
    assert result == expected


def test_DOC104(violations):
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
            3,
            "DOC104",
            "Parameter type mismatch with hint ({!r} != {!r})",
            ("str", "int"),
        ),
    )
    result = tuple(sphinxlinter.checker(parse_content(content), violations))
    assert result == expected


@pytest.mark.parametrize("repeated", [":type a: int", ":param int a:"])
def test_DOC105(repeated, violations):
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
        (3, "DOC105", "Duplicated parameter ({!r})", ("a",)),
    )
    result = tuple(sphinxlinter.checker(parse_content(content), violations))
    assert result == expected


def test_DOC106_single(violations):
    content = '''
def foo(a, b):
    """
    Title.

    :param int a: description
    :raises ValueError: description
    :param int b: description
    """

    pass
'''
    expected = (
        (3, 'DOC007', 'Misplaced section ({!r} after {!r})', ('param', 'raises',)),
    )
    result = tuple(sphinxlinter.checker(parse_content(content), violations))
    assert result == expected


def test_DOC106_multiple(violations):
    content = '''
def foo(a, b, c):
    """
    Title.

    :raises ValueError: description
    :param int b: description
    :return: description
    :type c: int
    """

    pass
'''
    expected = (
        (3, 'DOC007', 'Misplaced section ({!r} after {!r})', ('param', 'raises')),
        (3, 'DOC007', 'Misplaced section ({!r} after {!r})', ('type', 'raises')),
        (3, 'DOC007', 'Misplaced section ({!r} after {!r})', ('type', 'return')),
    )
    result = tuple(sphinxlinter.checker(parse_content(content), violations))
    assert result == expected


@pytest.mark.parametrize("value", [":return: description", ":rtype: int"])
def test_DOC201(value, violations):
    content = f'''
def foo():
    """
    Title.

    {value}
    """

    a = 1
'''

    expected = (
        (3, "DOC201", "Return documented but function has no return", ()),
    )
    result = tuple(sphinxlinter.checker(parse_content(content), violations))
    assert result == expected


def test_DOC202(violations):
    content = '''
def foo():
    """
    Title.

    :rtype: list[int,
    """

    return [1]
'''

    expected = (
        (3, "DOC202", "Invalid return type syntax ({!r})", ("list[int,",)),
    )
    result = tuple(sphinxlinter.checker(parse_content(content), violations))
    assert result == expected


def test_DOC203(violations):
    content = '''
def foo() -> int:
    """
    Title.

    :rtype: int
    """

    return 1
'''

    expected = (
        ((3, "DOC203", "Return type already in signature ({!r})", ("int",)),)
    )
    result = tuple(sphinxlinter.checker(parse_content(content), violations))
    assert result == expected


def test_DOC204(violations):
    content = '''
def foo() -> int:
    """
    Title.

    :rtype: str
    """

    return 1
'''

    expected = (
        (3, "DOC204", "Return type mismatch with annotation ({!r} != {!r})", ("str", "int")),
    )
    result = tuple(sphinxlinter.checker(parse_content(content), violations))
    assert result == expected


@pytest.mark.parametrize("key, repeated", [("rtype", ":rtype: int"), ("return", ":return: description)")])
def test_DOC205(key, repeated, violations):
    content = f'''
def foo():
    """
    Title.

    :rtype: int
    :return: description
    {repeated}
    """

    return 1
'''
    expected = (
        ((3, "DOC205", "Duplicated return section ({!r})", (key,)),)
    )
    result = tuple(sphinxlinter.checker(parse_content(content), violations))
    assert result == expected


def test_DOC302(violations):
    content = '''
def foo():
    """
    Title.

    :raise except: description
    """

    pass
'''

    expected = (
        ((3, "DOC302", "Invalid exception type syntax ({!r})", (True,)),)
    )
    result = tuple(sphinxlinter.checker(parse_content(content), violations))
    assert result == expected


def test_DOC305(violations):
    content = '''
def foo():
    """
    Title.

    :raises ValueError: description
    :raises TypeError, ValueError: description
    """

    pass
'''

    expected = (
        ((3, "DOC305", "Duplicated exception type ({!r})", ("ValueError",)),)
    )
    result = tuple(sphinxlinter.checker(parse_content(content), violations))
    assert result == expected


@pytest.mark.parametrize("return_key, return_section", [("rtype", ":rtype: int"), ("return", ":return: description)")])
def test_DOC306(violations, return_key, return_section):
    content = f'''
def foo():
    """
    Title.

    {return_section}
    :raises ValueError: description
    """

    pass
'''

    expected = (
        (3, "DOC007", "Misplaced section ({!r} after {!r})", ('raises', return_key)),
    )
    result = tuple(sphinxlinter.checker(parse_content(content), violations))
    assert result == expected
