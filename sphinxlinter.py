# -*- coding: utf-8 -*-

import argparse
import ast
import os
import pathlib
import re
import typing

# Docstring sections: https://www.sphinx-doc.org/en/master/usage/domains/python.html#info-field-lists
ptype_key = "type"
rtype_key = "rtype"
param_set = {"param", "parameter", "arg", "argument", "keyword", "key"}
return_set = {"return", "returns"}
raises_set = {"raises", "raise", "except", "exception"}
ignore_set = {"var", "ivar", "cvar", "vartype", "meta"}  # At this moment, it's ignored


class ParsedDocsParam(typing.NamedTuple):
    section_key: str
    param_name: str | None = None
    param_type: str | None = None


class ParsedDocsReturn(typing.NamedTuple):
    section_key: str
    return_type: str | None = None


class ParsedDocsRaise(typing.NamedTuple):
    section_key: str
    error_types: list[str] = []


class ParsedDocs(typing.NamedTuple):
    params: list[ParsedDocsParam]
    returns: list[ParsedDocsReturn]
    raises: list[ParsedDocsRaise]
    invalid: set[str]  # invalid sections


class Violations:
    # DOC0xx: Docstring section issues
    DOC001 = ("DOC001", "Unknown docstring section ({!r})")
    DOC002 = ("DOC002", "Malformed section ({!r})")
    DOC003 = ("DOC003", "Missing blank line after docstring")  # TODO
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
    # DOC3xx: Raises issues
    DOC301 = ("DOC301", "Invalid exception type syntax ({!r})")

    @staticmethod
    def is_valid_syntax(value, /):
        try:
            ast.parse(value, mode="eval")
            return True
        except SyntaxError:
            return False

    @classmethod
    def is_valid_type(cls, value, /):
        # Based on: (typing.ForwardRef.__init__)
        if cls.is_valid_syntax(value):
            if value.startswith('*'):
                value = f'({value},)[0]'  # E.g. (*Ts,)[0] or (*tuple[int, int],)[0]
            try:
                compile(value, '<string>', 'eval')
                return True
            except SyntaxError:
                return False
        else:
            return False

    @classmethod
    def validate_params(cls, parsed: ParsedDocs, parameters: dict[str, str | None], /):
        params_names = [p[1] for p in parsed.params if p[1]]
        for param in parsed.params:
            section_key, param_name, param_type = param
            type_hint = parameters.get(param_name)
            if not param_name or (section_key == ptype_key and not param_type):
                yield Violations.DOC002, (section_key,)
            if param_name and param_name not in parameters:
                yield Violations.DOC101, (param_name,)
            if param_type and not Violations.is_valid_type(param_type):
                yield Violations.DOC102, (param_type,)
            if param_type and type_hint and param_type == type_hint:
                yield Violations.DOC103, (param_type,)
            if param_type and type_hint and param_type != type_hint:
                yield Violations.DOC104, (param_type, type_hint)
            if param_name and params_names.count(param_name) > 1:
                yield Violations.DOC105, (param_name,)

    @classmethod
    def validate_return(cls, parsed: ParsedDocs, type_hint: str | None, has_returns: bool, /):
        if parsed.returns and not has_returns:
            yield Violations.DOC201, ()
        for _return in parsed.returns:
            section_key, return_type = _return
            if section_key == rtype_key and not return_type:
                yield Violations.DOC002, (section_key,)
            if return_type and not Violations.is_valid_type(return_type):
                yield Violations.DOC202, (return_type,)
            if return_type and type_hint and return_type == type_hint:
                yield Violations.DOC203, (return_type,)
            if return_type and type_hint and return_type != type_hint:
                yield Violations.DOC204, (return_type, type_hint)

    @classmethod
    def validate_raises(cls, parsed, /):
        for section_key, error_types in parsed.raises:
            if not error_types:
                yield Violations.DOC002, (section_key,)
            is_invalid = any(not Violations.is_valid_type(e) for e in error_types)
            if is_invalid:
                yield Violations.DOC301, (is_invalid,)

    @classmethod
    def discover(cls, parsed: ParsedDocs, parameters: dict[str, str | None], has_returns: bool, /):
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


def parse_section_rtype(section_key, parts_a, /):
    if not parts_a:  # ´:rtype:´
        return_type = None
    else:  # ´:rtype: [ReturnType]´
        return_type = " ".join(parts_a)
    return ParsedDocsReturn(section_key, return_type)


def parse_section_raise(section_key, parts_a, /):
    # ´:raise [ErrorTypes]: [ErrorDescription]´
    if len(parts_a) == 1:
        error_types = []
    else:
        error_types = "".join(parts_a[1:]).split(",")  # commas separate multiple error types
    return ParsedDocsRaise(section_key, error_types)


def parse_section_return(section_key, /):
    # ´:return: [ReturnDescription]´
    return ParsedDocsReturn(section_key)


def itersections(docstring, /):
    for match in re.finditer(r"(^:.*?)(?=^:|\Z)", docstring, flags=re.S | re.M | re.S):
        if chunk := match.group(0):
            yield chunk.strip()


def parse_docs(docstring, /):
    params = []
    raises = []
    returns = []
    invalid = set()
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
            returns.append(parse_section_return(section_key))
        elif section_key in ignore_set:
            continue
        else:
            invalid.add(section_key)

    return ParsedDocs(
        params=params,
        returns=returns,
        raises=raises,
        invalid=invalid,
    )


def is_return(func_def: ast.FunctionDef, /):
    body = func_def.body
    if not body:
        return False
    klasses = (ast.Yield, ast.YieldFrom, ast.Return)
    for node in body:
        if isinstance(node, klasses) or any(isinstance(child, klasses) for child in ast.walk(node)):
            return True
    return False


def get_args(func_def: ast.FunctionDef, /):
    yield from func_def.args.posonlyargs  # Positional-only args
    yield from func_def.args.args  # Regular args
    yield from func_def.args.kwonlyargs  # Keyword-only args
    yield from filter(None, (func_def.args.vararg, func_def.args.kwarg))  # *args, **kwargs


def get_parameters(func_def: ast.FunctionDef, /):
    result = {}
    for arg in get_args(func_def):
        result[arg.arg] = ast.unparse(ann) if (ann := arg.annotation) else None
    if func_def.returns:
        result["return"] = ast.unparse(func_def.returns)
    return result


def check_func(func_def: ast.FunctionDef, name: str, /, filename: str):
    docstring = ast.get_docstring(func_def) or ""
    line_number = func_def.lineno
    has_returns = is_return(func_def)
    parameters = get_parameters(func_def)
    parsed = parse_docs(docstring)

    for (code, message), value in Violations.discover(parsed, parameters, has_returns):
        print(f"{filename}:{line_number}: [{code}] {message.format(*value)}")


def check_file(pathlike, /):
    path = str(pathlike.resolve())
    tree = ast.parse(pathlike.read_bytes(), filename=path)
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            check_func(node, node.name, filename=path)
        elif isinstance(node, ast.ClassDef):
            class_name = node.name
            for item in node.body:
                if isinstance(item, ast.FunctionDef):
                    check_func(item, f"{class_name}.{item.name}", path)


def walk(paths, /):
    ignore_dirs = frozenset((".venv", ".env", ".git", ".pytest_cache", ".ruff_cache", "__pycache__", "site-packages"))
    for path in paths:
        if os.path.isfile(path) and path.endswith(".py"):
            yield pathlib.Path(path)
        elif os.path.isdir(path):
            for path in pathlib.Path(path).rglob("*.py"):
                if not any(part in ignore_dirs for part in path.parts):  # Skip ignored dirs
                    yield path


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Sphinx docstring checker")
    parser.add_argument("files", nargs="*", help="files or dirs to check", default=[os.getcwd()])
    args = parser.parse_args()
    for file in walk(args.files):
        check_file(file)
