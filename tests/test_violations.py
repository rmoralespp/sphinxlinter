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
    :var foo: description
    :ivar bar: description
    :cvar baz: description
    :vartype qux: int
    """

    pass
'''
    expected = (
        (3, "DOC001", "Invalid docstring section ({!r})", ("foo",)),
        (3, "DOC001", "Invalid docstring section ({!r})", ("bar",)),
        (3, 'DOC001', 'Invalid docstring section ({!r})', ('var',)),
        (3, 'DOC001', 'Invalid docstring section ({!r})', ('ivar',)),
        (3, 'DOC001', 'Invalid docstring section ({!r})', ('cvar',)),
        (3, 'DOC001', 'Invalid docstring section ({!r})', ('vartype',)),
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
    :var foo: description
    """

'''
    expected = (
        (3, 'DOC001', 'Invalid docstring section ({!r})', ('param',)),  # twice, but only once reported
        (3, 'DOC001', 'Invalid docstring section ({!r})', ('raises',)),
        (3, 'DOC001', 'Invalid docstring section ({!r})', ('return',)),
        (3, 'DOC001', 'Invalid docstring section ({!r})', ('rtype',)),
        (3, 'DOC001', 'Invalid docstring section ({!r})', ('var',)),
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
    # type
    ("type", ":type",),  # missing separator ":"
    ("type", ":type:",),  # missing separator name and type
    ("type", ":type:int",),  # missing parameter name
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
def test_DOC002_function(section, value, violations):
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


@pytest.mark.parametrize("section, value", [
    # missing separator ":" at the end
    ("ivar", ":ivar a",),
    ("cvar", ":cvar a",),
    # missing variable without name and description
    ("ivar", ":ivar:",),
    ("cvar", ":cvar:",),
    # missing variable name without description
    ("ivar", ":ivar foo:",),
    ("cvar", ":cvar foo:",),
    # missing variable without name  and description (only spaces)
    ("ivar", ":ivar:  ",),
    ("cvar", ":cvar:  ",),
    # missing type
    ("vartype", ":vartype a:",),
    # missing type (only spaces)
    ("vartype", ":vartype a: ",),
])
def test_DOC002_class(section, value, violations):
    content = f'''
class Foo:
    """
    Title.

    {value}
    """

    pass
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
        (3, "DOC005", "Too many consecutive blank lines", ()),
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
    "A one-line title\n\n:meta deprecated: foo",
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


@pytest.mark.parametrize("section, expected_section", [
    # param type
    (":type  a: str", ":type  a: str"),  # consecutive spaces between type and name
    (": type a: str", ": type a: str"),  # leading space before type keyword
    (":type a : str", ":type a : str"),  # trailing space after name
    (":type a:  str", ":type a:  str"),  # leading space before type hint
    (":type  a:  str", ":type  a:  str"),  # consecutive spaces both sides
    # param
    (":param  str  a: description", ":param  str  a:"),  # consecutive spaces
    (": param str a: description", ": param str a:"),  # leading space before param keyword
    (":param str a : description", ":param str a :"),  # trailing space after name
    (":param  str a: description", ":param  str a:"),  # leading space before type hint
    (":param str  a: description", ":param str  a:"),  # leading space before name
    # return
    (": return: description", ": return:"),  # leading space before return keyword
    (":return : description", ":return :"),  # trailing space after return keyword
    # # rtype
    (": rtype: int", ": rtype: int"),  # leading space before rtype keyword
    (":rtype : int", ":rtype : int"),  # trailing space after rtype keyword
    (":rtype:  int", ":rtype:  int"),  # leading space before type hint
    (": rtype :  int", ": rtype :  int"),  # leading and trailing space both sides
    # # raises
    (": raises ValueError: description", ": raises ValueError:"),  # leading ws before raises keyword
    (":raises  ValueError: description", ":raises  ValueError:"),  # consecutive ws after raises keyword
    (":raises ValueError : description", ":raises ValueError :"),  # trailing ws after error
    (":raises ValueError,  KeyError: description", ":raises ValueError,  KeyError:"),  # Consecutive ws after comma
    (":raises ValueError, KeyError : description", ":raises ValueError, KeyError :"),  # trailing ws after last error
    (":raises ValueError  , KeyError: description", ":raises ValueError  , KeyError:"),  # leading ws before comma
])
def test_DOC010_function(section, violations, expected_section):
    content = f'''
def foo(a):
    """
    Title.

    {section}
    """

    return a
'''
    expected = (
        (3, "DOC010", "Section definition contains invalid whitespace ({!r})", (expected_section,)),
    )
    result = tuple(sphinxlinter.checker(parse_content(content), violations))
    assert result == expected


@pytest.mark.parametrize("section", [
    ":param str a:  foo  bar  ",
    ":return:  foo  bar  ",
    ":raises ValueError:  foo  bar  ",
])
def test_DOC010_function_ignoring_descriptions_ws(section, violations):
    content = f'''
def foo(a):
    """
    Title.

    {section}
    """

    return a
'''
    expected = ()
    result = tuple(sphinxlinter.checker(parse_content(content), violations))
    assert result == expected


@pytest.mark.parametrize("section, expected_section", [
    # var type
    (":vartype  a: int", ":vartype  a: int"),  # consecutive spaces between vartype and name
    (": vartype a: int", ": vartype a: int"),  # leading space before vartype keyword
    (":vartype a : int", ":vartype a : int"),  # trailing space after name
    (":vartype a:  int", ":vartype a:  int"),  # leading space before type hint
    (":vartype  a:  int", ":vartype  a:  int"),  # consecutive spaces both sides
    # ivar
    (":ivar  a: description", ":ivar  a:"),  # consecutive spaces
    (": ivar a: description", ": ivar a:"),  # leading space before ivar keyword
    (":ivar a : description", ":ivar a :"),  # trailing space after name
    # cvar
    (":cvar  a: description", ":cvar  a:"),  # consecutive spaces
    (": cvar a: description", ": cvar a:"),  # leading space before cvar keyword
    (":cvar a : description", ":cvar a :"),  # trailing space after name
])
def test_DOC010_class(section, expected_section, violations):
    content = f'''
class Foo:
    """
    Title.

    {section}
    """

    pass
'''
    expected = (
        (3, "DOC010", "Section definition contains invalid whitespace ({!r})", (expected_section,)),
    )
    result = tuple(sphinxlinter.checker(parse_content(content), violations))
    assert result == expected


@pytest.mark.parametrize("section", [
    ":ivar a:  foo  bar  ",
    ":cvar a:  foo  bar  ",
])
def test_DOC010_class_ignoring_descriptions_ws(section, violations):
    content = f'''
class Foo:
    """
    Title.

    {section}
    """

    pass
'''
    expected = ()
    result = tuple(sphinxlinter.checker(parse_content(content), violations))
    assert result == expected


def test_DOC011_function(violations):
    content = '''
def foo():
    """
    Title.

    :rtype: int
    Trailing description.
    """
    '''

    expected = ((3, 'DOC011', 'Trailing non-empty lines after last section.', ()),)
    result = tuple(sphinxlinter.checker(parse_content(content), violations))
    assert result == expected


def test_DOC011_class(violations):
    content = '''
class Foo:
    """
    Title.

    :vartype a: int
    Trailing description.
    """
    '''
    expected = ((3, 'DOC011', 'Trailing non-empty lines after last section.', ()),)
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
            "Parameter type mismatch with annotation ({!r} != {!r})",
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
        (3, 'DOC007', 'Misplaced section ({!r} appears after {!r})', ('param', 'raises',)),
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
        (3, 'DOC007', 'Misplaced section ({!r} appears after {!r})', ('param', 'raises')),
        (3, 'DOC007', 'Misplaced section ({!r} appears after {!r})', ('type', 'raises')),
        (3, 'DOC007', 'Misplaced section ({!r} appears after {!r})', ('type', 'return')),
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
        (3, "DOC201", "Return documented but function has no return statement", ()),
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
        (3, "DOC007", "Misplaced section ({!r} appears after {!r})", ('raises', return_key)),
    )
    result = tuple(sphinxlinter.checker(parse_content(content), violations))
    assert result == expected


def test_DOC402(violations):
    content = '''
class Foo:
    """
    Title.

    :vartype a: list[str,
    """

    pass
'''

    expected = (
        ((3, 'DOC402', 'Invalid variable type syntax ({!r})', ('list[str,',)),)
    )
    result = tuple(sphinxlinter.checker(parse_content(content), violations))
    assert result == expected


@pytest.mark.parametrize("section, value", [
    ("ivar", ":ivar foo bar: description",),
    ("cvar", ":cvar foo bar: description",),
    ("vartype", ":vartype foo bar: int",),
])
def test_DOC403(section, value, violations):
    content = f'''
class Foo:
    """
    Title.

    {value}
    """

    pass
'''
    expected = ((3, 'DOC403', 'Variable name contains invalid whitespace ({!r})', ('foo bar',)),)
    result = tuple(sphinxlinter.checker(parse_content(content), violations))
    assert result == expected


def test_DOC405(violations):
    content = '''
class Foo:
    """
    Title.

    :ivar bar: description
    :ivar bar: description
    """

    pass
'''
    expected = ((3, 'DOC405', 'Duplicated variable ({!r})', ('bar',)),)
    result = tuple(sphinxlinter.checker(parse_content(content), violations))
    assert result == expected
