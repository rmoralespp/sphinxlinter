# -*- coding: utf-8 -*-

import argparse
import ast
import collections
import os
import pathlib
import re
import sys
import typing

# Docstring sections: https://www.sphinx-doc.org/en/master/usage/domains/python.html#info-field-lists
ptype_key = "type"
rtype_key = "rtype"
param_set = {"param", "parameter", "arg", "argument", "keyword", "key"}
return_set = {"return", "returns"}
raises_set = {"raises", "raise", "except", "exception"}
ignore_set = {"var", "ivar", "cvar", "vartype", "meta"}  # At this moment, it's ignored

# Regex to find docstring sections (start with ':' and end before next ':' at start of line or end of string)
isections = re.compile(r"(^:.*?)(?=^:|\Z)", flags=re.DOTALL | re.MULTILINE).finditer


class ParsedDocsParam(typing.NamedTuple):
    section_key: str
    param_name: str | None = None
    param_type: str | None = None


class ParsedDocsReturn(typing.NamedTuple):
    section_key: str
    return_type: str | None = None
    description: str | None = None  # Only for ´:return:´


class ParsedDocsRaise(typing.NamedTuple):
    section_key: str
    error_types: list[str] = []


class ParsedDocs(typing.NamedTuple):
    params: list[ParsedDocsParam]
    returns: list[ParsedDocsReturn]
    raises: list[ParsedDocsRaise]
    invalid: set[str]  # invalid sections

    docs: str | None = None  # The full docstring
    docs_ini_lineno: int | None = None  # First line number of the docstring, None if no docstring
    docs_end_lineno: int | None = None  # End line number of the docstring, None if no docstring
    code_ini_lineno: int | None = None  # First line number of the code block after the docstring, None if no code


class Violations:
    # DOC0xx: Docstring section issues
    DOC001 = ("DOC001", "Unknown docstring section ({!r})")
    DOC002 = ("DOC002", "Malformed section ({!r})")
    DOC003 = ("DOC003", "Missing blank line after docstring")
    DOC004 = ("DOC004", "Missing blank line between summary and sections")  # TODO
    # DOC1xx: Argument issues
    DOC101 = ("DOC101", "Parameter documented but not in signature ({!r})")
    DOC102 = ("DOC102", "Invalid parameter type syntax ({!r})")
    DOC103 = ("DOC103", "Parameter type already in signature ({!r})")
    DOC104 = ("DOC104", "Parameter type mismatch with hint ({!r} != {!r})")
    DOC105 = ("DOC105", "Duplicate parameter ({!r})")
    # DOC2xx: Return issues
    DOC201 = ("DOC201", "Return documented but function has no return")
    DOC202 = ("DOC202", "Invalid return type syntax ({!r})")
    DOC203 = ("DOC203", "Return type already in signature ({!r})")
    DOC204 = ("DOC204", "Return type mismatch with annotation ({!r} != {!r})")
    # DOC3xx: Raise issues
    DOC301 = ("DOC301", "Invalid exception type syntax ({!r})")

    @staticmethod
    def is_valid_syntax(value, /):
        try:
            ast.parse(value, mode="eval")
            return True
        except SyntaxError:
            return False

    @classmethod
    def is_valid_type_hint(cls, hint, /):
        if hint:
            try:
                ast.parse(f"x: {hint}")
                return True
            except SyntaxError:
                return False
        else:
            return False

    @classmethod
    def validate_params(cls, parsed, parameters, /):
        count = collections.Counter(param[1] for param in parsed.params if param[1])
        for param in parsed.params:
            section_key, param_name, param_type = param
            type_hint = parameters.get(param_name)
            # :param:´ without name or ´:type:´ without type or name
            if not param_name or (section_key == ptype_key and not param_type):
                yield Violations.DOC002, (section_key,)
            if param_name and param_name not in parameters:  # Documented but not in signature
                yield Violations.DOC101, (param_name,)
            if param_type and not Violations.is_valid_type_hint(param_type):  # Invalid type syntax
                yield Violations.DOC102, (param_type,)
            if param_type and type_hint and param_type == type_hint:  # Redundant type
                yield Violations.DOC103, (param_type,)
            if param_type and type_hint and param_type != type_hint:  # Mismatched type
                yield Violations.DOC104, (param_type, type_hint)
            if param_name and count[param_name] > 1:  # Duplicate parameter
                yield Violations.DOC105, (param_name,)

    @classmethod
    def validate_return(cls, parsed, type_hint, has_returns, /):
        if parsed.returns and not has_returns:
            yield Violations.DOC201, ()  # Return documented but function has no return
        for _return in parsed.returns:
            section_key, return_type, description = _return

            if section_key in return_set and not description:  # ´:return:´ without description
                yield Violations.DOC002, (section_key,)
            if section_key == rtype_key and not return_type:  # ´:rtype:´ without type
                yield Violations.DOC002, (section_key,)

            if return_type and not Violations.is_valid_type_hint(return_type):  # Invalid return type
                yield Violations.DOC202, (return_type,)
            if return_type and type_hint and return_type == type_hint:  # Redundant return type
                yield Violations.DOC203, (return_type,)
            if return_type and type_hint and return_type != type_hint:  # Mismatched return type
                yield Violations.DOC204, (return_type, type_hint)

    @classmethod
    def validate_raises(cls, parsed, /):
        for section_key, error_types in parsed.raises:
            if not error_types:  # ´:raise:´ without error types
                yield Violations.DOC002, (section_key,)
            is_invalid = any(not Violations.is_valid_syntax(e) for e in error_types)
            if is_invalid:  # Invalid exception type syntax
                yield Violations.DOC301, (is_invalid,)

    @classmethod
    def discover(cls, parsed, parameters, has_returns, /):
        if parsed.code_ini_lineno and parsed.docs_end_lineno and parsed.code_ini_lineno - parsed.docs_end_lineno == 1:
            yield Violations.DOC003, ()
        yield from ((Violations.DOC001, (section_key,)) for section_key in parsed.invalid)
        yield from cls.validate_params(parsed, parameters)
        yield from cls.validate_return(parsed, parameters.get("return"), has_returns)
        yield from cls.validate_raises(parsed)


def parse_section_param(section_key, parts_a, /):
    if len(parts_a) == 1:  # ´:param:´
        param_name = None
        param_type = None
    elif len(parts_a) == 2:  # ´:param [ParamName]:´
        param_name = parts_a[1]
        param_type = None
    else:  # ´:param [ParamType] [ParamName]:´
        param_type = " ".join(parts_a[1:-1])  # unsplit type
        param_name = parts_a[-1]
    return ParsedDocsParam(section_key, param_name, param_type)


def parse_section_type(section_key, parts_a, parts_b, /):
    if len(parts_a) == 1:  # ´:type´
        param_name = None
    else:  # >=2   ´:type [ParamName]´
        param_name = " ".join(parts_a[1:])
    if not parts_b:  # ´:type [ParamName]´
        param_type = None
    else:  # ´:type [ParamName]: [ParamType]´
        param_type = " ".join(parts_b)
    return ParsedDocsParam(section_key, param_name, param_type)


def parse_section_rtype(section_key, parts_b, /):
    if not parts_b:  # ´:rtype:´
        return_type = None
    else:  # ´:rtype: [ReturnType]´
        return_type = " ".join(parts_b)
    return ParsedDocsReturn(section_key, return_type)


def parse_section_raise(section_key, parts_a, /):
    # ´:raise [ErrorTypes]: [ErrorDescription]´
    if len(parts_a) == 1:
        error_types = []
    else:
        error_types = "".join(parts_a[1:]).split(",")  # commas separate multiple error types
    return ParsedDocsRaise(section_key, error_types)


def parse_section_return(section_key, parts_a, parts_b, /):
    if parts_b:  # ´:return: [ReturnDescription]´
        description = " ".join(parts_b[1:])
    else:
        description = None  # ´:return:´ without description
    return ParsedDocsReturn(section_key, description=description)


def itersections(docstring, /):
    if docstring:
        yield from (chunk.strip() for match in isections(docstring) if (chunk := match.group(0)))


def parse_docs(node, /):
    params = []
    raises = []
    returns = []
    invalid = set()
    docstring = ast.get_docstring(node)

    for section in itersections(docstring):
        a, _, b = section.lstrip(":").partition(":")
        b = b.splitlines()[0].strip() if b else ""  # Only first line
        parts_a = a.split()
        parts_b = b.split()
        section_key = parts_a[0].lower()
        if section_key in param_set:
            params.append(parse_section_param(section_key, parts_a))
        elif section_key == ptype_key:
            params.append(parse_section_type(section_key, parts_a, parts_b))
        elif section_key in rtype_key:
            returns.append(parse_section_rtype(section_key, parts_b))
        elif section_key in raises_set:
            raises.append(parse_section_raise(section_key, parts_a))
        elif section_key in return_set:
            returns.append(parse_section_return(section_key, parts_a, parts_b))
        elif section_key not in ignore_set:
            invalid.add(section_key)

    if docstring:
        first = node.body[0]
        docs_ini_lineno, docs_end_lineno = (first.lineno, first.end_lineno)
        code_ini_lineno = node.body[1].lineno if len(node.body) > 1 else None
    else:
        docs_ini_lineno = docs_end_lineno = None
        code_ini_lineno = node.body[0].lineno if node.body else None

    return ParsedDocs(
        docs=docstring,
        docs_ini_lineno=docs_ini_lineno,
        docs_end_lineno=docs_end_lineno,
        code_ini_lineno=code_ini_lineno,
        params=params,
        returns=returns,
        raises=raises,
        invalid=invalid,
    )


def has_return_or_yield(node, /):
    """
    Returns True if the given AST node (ast.FunctionDef or ast.AsyncFunctionDef)
    contains a 'return', 'yield', or 'yield from' statement in its main body
    (excluding nested functions).

    :param ast.AST node: Root node to explore.
    :rtype: bool
    """

    class ReturnYieldVisitor(ast.NodeVisitor):
        def __init__(self):
            self.found = False
            self.depth = 0

        def visit_FunctionDef(self, node):
            if self.depth == 0:
                self.depth += 1
                self.generic_visit(node)
                self.depth -= 1

        def visit_AsyncFunctionDef(self, node):
            if self.depth == 0:
                self.depth += 1
                self.generic_visit(node)
                self.depth -= 1

        def visit_Return(self, node):
            if self.depth == 1:
                self.found = True

        def visit_Yield(self, node):
            if self.depth == 1:
                self.found = True

        def visit_YieldFrom(self, node):
            if self.depth == 1:
                self.found = True

    visitor = ReturnYieldVisitor()
    visitor.visit(node)
    return visitor.found


def get_args(node, /):
    yield from node.args.posonlyargs  # Positional-only args
    yield from node.args.args  # Regular args
    yield from node.args.kwonlyargs  # Keyword-only args
    yield from filter(None, (node.args.vararg, node.args.kwarg))  # *args, **kwargs


def get_params(node, /):
    for arg in get_args(node):
        yield (arg.arg, ast.unparse(ann) if (ann := arg.annotation) else None)
    if node.returns:
        yield ("return", ast.unparse(node.returns))


def check_func(filename, node, /):
    lineno = node.lineno
    has_returns = has_return_or_yield(node)
    params = dict(get_params(node))
    parsed = parse_docs(node)
    fmt = "{}:{}: [{}] {}".format

    result = True
    for (code, msg), ctx in Violations.discover(parsed, params, has_returns):
        print(fmt(filename, lineno, code, msg.format(*ctx)))
        result = False

    return result


def walk_module(data, filename, /):
    """
    Yields each function node from the parsed "data" tree.

    :param bytes data: Content to parse.
    :param str filename: File name to use when printing messages.
    :return: Each root node of every function/method.
    :rtype: Iterator[ast.FunctionDef | ast.AsyncFunctionDef]
    """

    try:
        tree = ast.parse(data, filename=filename)
    except SyntaxError:
        pass
    else:
        klasses = (ast.FunctionDef, ast.AsyncFunctionDef)
        for node in ast.walk(tree):
            if isinstance(node, klasses):
                yield node


def walk(paths, ignore_dirs, /):
    ignore_dirs = frozenset(ignore_dirs)
    for path in paths:
        if os.path.isfile(path) and path.endswith(".py"):
            yield pathlib.Path(path)
        elif os.path.isdir(path):
            for rpath in pathlib.Path(path).rglob("*.py"):
                if not any(part in ignore_dirs for part in rpath.parts):  # Skip ignored dirs
                    yield rpath


def main():
    ignore = [".venv", ".env", ".git", ".pytest_cache", ".ruff_cache", "__pycache__", "site-packages"]
    parser = argparse.ArgumentParser(description="Sphinx docstring checker")
    parser.add_argument("files", nargs="*", help="files or dirs to check", default=[os.getcwd()])
    parser.add_argument("--ignore", nargs="*", help="directories to ignore", default=ignore)
    args = parser.parse_args()
    result = False
    for path in walk(args.files, args.ignore):
        filename = str(path)
        for node in walk_module(path.read_bytes(), filename):
            if not check_func(filename, node):
                result = True

    return 1 if result else 0


if __name__ == "__main__":
    sys.exit(main())
