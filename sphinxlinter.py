# -*- coding: utf-8 -*-

import argparse
import ast
import collections
import inspect
import itertools
import logging
import operator
import os.path
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

# Summary (everything before the first section or the end of the string)
summary_regex = re.compile(r'^(.*?)(?=^:|\Z)', flags=re.DOTALL | re.MULTILINE)
# Section (start with ':' and end before next ':' at start of line or end of string)
section_regex = re.compile(r'(^:.*?)(?=^:|\Z)', flags=re.DOTALL | re.MULTILINE)
# Trailing empty lines
trailing_regex = re.compile("(?:^\\s*$){2,}\\Z", flags=re.MULTILINE)
# Consecutive empty lines (not at end)
empty_lines_regex = re.compile("(?:^[ \t]*\r?\n){2,}(?=[^\r\n])", re.MULTILINE)


class ParsedDocsParam(typing.NamedTuple):
    section_key: str
    sep: bool  # True if ':' was present
    param_name: str | None
    param_type: str | None
    order: int  # Order of appearance in the docstring


class ParsedDocsReturn(typing.NamedTuple):
    section_key: str
    sep: bool  # True if ':' was present
    return_type: str | None
    description: str | None  # Only for ´:return:´
    section_ctx: bool  # True if context was present (e.g. ´:return context: description´ or ´:rtype context: type´)
    order: int  # Order of appearance in the docstring


class ParsedDocsRaise(typing.NamedTuple):
    section_key: str
    sep: bool  # True if ':' was present
    error_types: list[str]
    order: int  # Order of appearance in the docstring


class ParsedDocs(typing.NamedTuple):
    summary: str | None  # The summary section (before the first section)
    params: list[ParsedDocsParam]
    returns: list[ParsedDocsReturn]
    raises: list[ParsedDocsRaise]
    invalid: list[str]  # invalid sections

    rawdocs: str | None  # Raw docstring
    docs: str | None  # The full docstring
    docs_ini_lineno: int | None  # First line number of the docstring, None if no docstring
    docs_end_lineno: int | None  # End line number of the docstring, None if no docstring
    code_ini_lineno: int | None  # First line number of the code block after the docstring, None if no code


class Violations:
    # Rules definition:
    #   Enabled, Code, Message

    # DOC0xx: Docstring section issues
    DOC001 = (True, "DOC001", "Unknown docstring section ({!r})")
    DOC002 = (True, "DOC002", "Malformed section ({!r})")
    DOC003 = (True, "DOC003", "Missing blank line after docstring")
    DOC004 = (True, "DOC004", "Missing blank line between summary and sections")
    DOC005 = (True, "DOC005", "Too many consecutive empty lines")
    DOC006 = (True, "DOC006", "Trailing empty lines")
    DOC007 = (True, "DOC007", "Misplaced section ({!r} after {!r})")

    # DOC1xx: Parameter issues
    DOC101 = (True, "DOC101", "Parameter documented but not in signature ({!r})")
    DOC102 = (True, "DOC102", "Invalid parameter type syntax ({!r})")
    DOC103 = (True, "DOC103", "Parameter type already in signature ({!r})")
    DOC104 = (True, "DOC104", "Parameter type mismatch with hint ({!r} != {!r})")
    DOC105 = (True, "DOC105", "Duplicated parameter ({!r})")

    # DOC2xx: Return issues
    DOC201 = (True, "DOC201", "Return documented but function has no return")
    DOC202 = (True, "DOC202", "Invalid return type syntax ({!r})")
    DOC203 = (True, "DOC203", "Return type already in signature ({!r})")
    DOC204 = (True, "DOC204", "Return type mismatch with annotation ({!r} != {!r})")
    DOC205 = (True, "DOC205", "Duplicated return section ({!r})")

    # DOC3xx: Raises issues
    DOC302 = (True, "DOC302", "Invalid exception type syntax ({!r})")
    DOC305 = (True, "DOC305", "Duplicated exception type ({!r})")

    _get_order = operator.attrgetter("order")

    def __init__(self, /, *, enable=None, disable=None):
        is_rule = re.compile("^DOC\\d+$").match
        all_rules = filter(is_rule, dir(self))
        if not enable:
            selected = set(name for name in all_rules if getattr(self, name)[0])
        elif "ALL" in enable:
            selected = set(all_rules)
        else:
            selected = set(enable)

        # Apply disable after enable, so disable has precedence
        if disable is not None:
            selected.difference_update(disable)

        self.valid = frozenset(selected)
        self.stats = collections.Counter()

    @staticmethod
    def is_valid_syntax(value, /, mode="eval"):
        try:
            ast.parse(value, mode=mode)
            return True
        except SyntaxError:
            return False

    @classmethod
    def is_valid_type_hint(cls, hint, /):
        return cls.is_valid_syntax(f"x: {hint}", mode="exec") if hint else False

    @classmethod
    def validate_empty_lines(cls, parsed, /):
        text = parsed.rawdocs
        if text:
            hits = empty_lines_regex.finditer(text)
            present = next(filter(None, hits), None)
            if present:
                yield cls.DOC005, ()

            hits = trailing_regex.finditer(text)
            present = next(filter(None, hits), None)
            if present:
                yield cls.DOC006, ()

    @classmethod
    def validate_summary(cls, parsed, /):
        if parsed.summary:
            summary_lines = parsed.summary.splitlines()
            br_tail_count = sum(1 for _ in itertools.takewhile(operator.not_, reversed(summary_lines)))

            if br_tail_count == 0 and (parsed.params + parsed.returns + parsed.raises):
                # Only applies if there are sections after the summary
                yield cls.DOC004, ()  # Missing blank line between summary and sections

    @classmethod
    def validate_params(cls, parsed, parameters, /):
        bag = set()
        first_raises = min(parsed.raises, key=cls._get_order, default=None)
        first_return = min(parsed.returns, key=cls._get_order, default=None)
        for param in parsed.params:
            section_key, sep, name, kind, order = param
            type_hint = parameters.get(name)
            # Malformed param: missing ':' or missing name/type when required
            if not (sep and name) or (section_key == ptype_key and not kind):
                yield cls.DOC002, (section_key,)
            if name and name not in parameters:  # Documented but not in signature
                yield cls.DOC101, (name,)
            if kind and not cls.is_valid_type_hint(kind):  # Invalid type syntax
                yield cls.DOC102, (kind,)
            if kind and type_hint and kind == type_hint:  # Redundant type
                yield cls.DOC103, (kind,)
            if kind and type_hint and kind != type_hint:  # Mismatched type
                yield cls.DOC104, (kind, type_hint)

            if name and name in bag:  # Duplicated parameter
                yield cls.DOC105, (name,)

            if first_raises and order > first_raises.order:
                # Params after raises are considered misplaced
                yield cls.DOC007, (section_key, first_raises.section_key,)
            if first_return and order > first_return.order:
                # Params after returns are considered misplaced
                yield cls.DOC007, (section_key, first_return.section_key,)

            if name:
                bag.add(name)

    @classmethod
    def validate_return(cls, parsed, type_hint, has_returns, is_implemented, /):
        if parsed.returns and (not has_returns and is_implemented):
            yield cls.DOC201, ()  # Return documented but implementation has no return

        bag = set()
        for doc_return in parsed.returns:
            section_key, sep, return_type, description, section_key_ctx, order = doc_return
            # Malformed return: missing ':' or missing type/description when required or invalid context
            if not sep or section_key_ctx:
                # Missing ':' separator or invalid context (section_key_ctx is True)
                yield cls.DOC002, (section_key,)
            elif section_key in return_set and not description:
                # :return:´ without description
                yield cls.DOC002, (section_key,)
            elif section_key == rtype_key and not return_type:  # ´:rtype:´ without type
                yield cls.DOC002, (section_key,)
            # Invalid or redundant return type checks
            if return_type and not cls.is_valid_type_hint(return_type):  # Invalid return type
                yield cls.DOC202, (return_type,)
            if return_type and type_hint and return_type == type_hint:  # Redundant return type
                yield cls.DOC203, (return_type,)
            if return_type and type_hint and return_type != type_hint:  # Mismatched return type
                yield cls.DOC204, (return_type, type_hint)
            # Duplicate return section
            if section_key in bag:
                yield cls.DOC205, (section_key,)  # Duplicate return section
            bag.add(section_key)

    @classmethod
    def validate_raises(cls, parsed, /):
        bag = set()
        first_return = min(parsed.returns, key=cls._get_order, default=None)

        for section_key, sep, error_types, order in parsed.raises:
            if not (sep and error_types):  # Missing ':' or missing error types
                yield cls.DOC002, (section_key,)

            is_invalid = any(not cls.is_valid_syntax(e) for e in error_types)
            if is_invalid:  # Invalid exception type syntax
                yield cls.DOC302, (is_invalid,)

            for error_type in error_types:
                if error_type in bag:  # Duplicate exception type
                    yield cls.DOC305, (error_type,)
                bag.add(error_type)

            if first_return and order > first_return.order:
                # Raises after returns are considered misplaced
                yield cls.DOC007, (section_key, first_return.section_key,)

    @classmethod
    def discover_all(cls, parsed, parameters, has_returns, is_implemented, /):
        if parsed.code_ini_lineno and parsed.docs_end_lineno and parsed.code_ini_lineno - parsed.docs_end_lineno == 1:
            yield cls.DOC003, ()
        yield from ((cls.DOC001, (section_key,)) for section_key in parsed.invalid)

        yield from cls.validate_empty_lines(parsed)
        yield from cls.validate_summary(parsed)
        yield from cls.validate_params(parsed, parameters)
        yield from cls.validate_return(parsed, parameters.get("return"), has_returns, is_implemented)
        yield from cls.validate_raises(parsed)

    def discover(self, parsed, parameters, has_returns, is_implemented, /):
        for (_, code, msg), ctx in self.discover_all(parsed, parameters, has_returns, is_implemented):
            if code in self.valid:
                self.stats[code] += 1
                yield ((code, msg), ctx)


def parse_section_param(section_key, sep, parts_a, order, /):
    if len(parts_a) == 1:  # ´:param:´
        param_name = None
        param_type = None
    elif len(parts_a) == 2:  # ´:param [ParamName]:´
        param_name = parts_a[1]
        param_type = None
    else:  # ´:param [ParamType] [ParamName]:´
        param_type = " ".join(parts_a[1:-1])  # unsplit type
        param_name = parts_a[-1]
    return ParsedDocsParam(section_key, sep, param_name, param_type, order)


def parse_section_type(section_key, sep, parts_a, parts_b, order, /):
    if len(parts_a) == 1:  # ´:type:´
        param_name = None
    else:  # >=2   ´:type [ParamName]:´
        param_name = " ".join(parts_a[1:])

    if parts_b:  # ´:type [ParamName]: [ParamType]´
        param_type = " ".join(parts_b)
    else:  # ´:type [ParamName]:´ (without type)
        param_type = None
    return ParsedDocsParam(section_key, sep, param_name, param_type, order)


def parse_section_rtype(section_key, sep, parts_a, parts_b, order, /):
    section_key_ctx = len(parts_a) > 1  # e.g. ´:rtype context: type´
    if parts_b:  # ´:rtype: [ReturnType]´
        return_type = " ".join(parts_b)
    else:  # ´:rtype:´ (without type)
        return_type = None
    return ParsedDocsReturn(section_key, sep, return_type, None, section_key_ctx, order)


def parse_section_raise(section_key, sep, parts_a, order, /):
    if len(parts_a) == 1:  # ´:raise [ErrorType]: [ErrorDescription]´
        error_types = []
    else:  # >=2  ´:raise [ErrorType1, ErrorType2]: [ErrorDescription]´
        error_types = "".join(parts_a[1:]).split(",")  # commas separate multiple error types
    return ParsedDocsRaise(section_key, sep, error_types, order)


def parse_section_return(section_key, sep, parts_a, parts_b, order, /):
    section_key_ctx = len(parts_a) > 1  # e.g. ´:return context: description´
    if parts_b:  # ´:return: [ReturnDescription]´
        description = " ".join(parts_b)
    else:  # ´:return:´ (without description)
        description = None
    return ParsedDocsReturn(section_key, sep, None, description, section_key_ctx, order)


def itersections(docstring, /):
    if docstring:
        yield from (chunk.strip() for match in section_regex.finditer(docstring) if (chunk := match.group(0)))


def get_summary(docstring, /):
    if docstring and (match := summary_regex.match(docstring)):
        return match.group(0)
    else:
        return None


def parse_docs(node, /):
    params = list()
    raises = list()
    returns = list()
    invalid = list()
    rawdocs = ast.get_docstring(node, clean=False)
    docstring = rawdocs if rawdocs is None else inspect.cleandoc(rawdocs)

    for order, section in enumerate(itersections(docstring)):
        a, sep, b = section.lstrip(":").partition(":")
        sep = bool(sep)  # True if ':' was present
        b = b.splitlines()[0].strip() if (b := b.strip()) else ""  # Only first line of description is relevant.
        parts_a = a.split()
        parts_b = b.split()
        section_key = parts_a[0].lower()
        if section_key in param_set:
            params.append(parse_section_param(section_key, sep, parts_a, order))
        elif section_key == ptype_key:
            params.append(parse_section_type(section_key, sep, parts_a, parts_b, order))
        elif section_key in rtype_key:
            returns.append(parse_section_rtype(section_key, sep, parts_a, parts_b, order))
        elif section_key in raises_set:
            raises.append(parse_section_raise(section_key, sep, parts_a, order))
        elif section_key in return_set:
            returns.append(parse_section_return(section_key, sep, parts_a, parts_b, order))
        elif section_key not in ignore_set:
            invalid.append(section_key)

    if docstring:
        summary = get_summary(docstring)
        first = node.body[0]
        docs_ini_lineno, docs_end_lineno = (first.lineno, first.end_lineno)
        code_ini_lineno = node.body[1].lineno if len(node.body) > 1 else None
    else:
        summary = None
        docs_ini_lineno = docs_end_lineno = None
        code_ini_lineno = node.body[0].lineno if node.body else None

    return ParsedDocs(
        summary=summary,
        rawdocs=rawdocs,
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

    :param ast.FunctionDef | ast.AsyncFunctionDef node: Root node to explore.

    :return: Whether the function has either "return" or "yield".
    :rtype: bool
    """

    class ReturnYieldVisitor(ast.NodeVisitor):
        def __init__(self, /):
            self.found = False
            self.depth = 0

        def visit_nested(self, node, /):
            if self.depth == 0:
                self.depth += 1
                self.generic_visit(node)
                self.depth -= 1

        def visit_FunctionDef(self, node, /):
            self.visit_nested(node)

        def visit_AsyncFunctionDef(self, node, /):
            self.visit_nested(node)

        def visit_Return(self, node, /):
            self.found = True

        def visit_Yield(self, node, /):
            self.found = True

        def visit_YieldFrom(self, node, /):
            self.found = True

    visitor = ReturnYieldVisitor()
    visitor.visit(node)
    return visitor.found


def is_not_implemented(node, /, rawdocs=None):
    """
    Returns True if the given AST node's body contains exactly one statement
    and that statement is one of the following:
      - `pass`
      - `raise NotImplementedError` or `raise NotImplementedError()`
      - `...` (Ellipsis literal)
    Otherwise, returns False.

    :param ast.FunctionDef | ast.AsyncFunctionDef node: Root node to explore.
    :param str | None rawdocs: Raw docstring.

    :rtype: bool
    """

    if rawdocs and len(node.body) > 2 or (not rawdocs and len(node.body) > 1):
        return False  # More than one statement
    elif rawdocs and len(node.body) == 1:
        return True  # Only docstring, no code
    else:  # One statement (without docstring or after docstring)
        stmt = node.body[-1]

        if isinstance(stmt, ast.Pass):  # Case: "pass"
            return True

        elif isinstance(stmt, ast.Raise):  # Case: "raise NotImplementedError()"
            exc = stmt.exc
            error_name = NotImplementedError.__name__
            if (
                    isinstance(exc, ast.Call)
                    and isinstance(exc.func, ast.Name)
                    and exc.func.id == error_name
            ):
                return True

            else:  # Case: "raise NotImplementedError"
                return isinstance(exc, ast.Name) and exc.id == error_name

        elif isinstance(stmt, ast.Expr):  # Case: "..."
            return isinstance(stmt.value, ast.Constant) and (stmt.value.value is Ellipsis)
        else:
            return False


def checker(node, violations, /):
    """
    Returns True if the given AST node (ast.FunctionDef or ast.AsyncFunctionDef)
    contains a 'return', 'yield', or 'yield from' statement in its main body
    (excluding nested functions).

    :param ast.FunctionDef | ast.AsyncFunctionDef node: Root node to explore.
    :param Violations violations: Violations instance with enabled/disabled rules.

    :return: Generator with data of each violation.
    :rtype: typing.Iterator[tuple[int, str, dict]]
    """

    params = dict(get_params(node))
    parsed = parse_docs(node)
    lineno = parsed.docs_ini_lineno
    has_returns = has_return_or_yield(node)
    is_implemented = not is_not_implemented(node, rawdocs=parsed.rawdocs)

    for (code, msg), ctx in violations.discover(parsed, params, has_returns, is_implemented):
        yield (lineno, code, msg, ctx)


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


def check_node(node, violations, /):
    for lineno, code, msg, ctx in checker(node, violations):
        yield (lineno, code, msg.format(*ctx))


def walk_module(quiet, data, filename, /):
    """
    Yields each function node from the parsed "data" tree.

    :param bool quiet: If False, print warnings to stderr.
    :param bytes data: Content to parse.
    :param str filename: File name to use when printing messages.

    :return: Each root node of every function/method.
    :rtype: Iterator[ast.FunctionDef | ast.AsyncFunctionDef]
    """

    try:
        tree = ast.parse(data, filename=filename)
    except SyntaxError as e:
        if not quiet:
            logging.warning("%s: %s", filename, e)
    else:
        klasses = (ast.FunctionDef, ast.AsyncFunctionDef)
        for node in ast.walk(tree):
            if isinstance(node, klasses):
                yield node


def walk(paths, ignore_dirs, /):
    suffix = ".py"
    for item in paths:
        path = pathlib.Path(item)
        if path.is_file():
            # The user requested this file.
            # return it even if it does not end with .py
            yield path
        elif path.is_dir():
            for root, directories, files in path.walk():
                # Remove ignored directories
                for candidate in frozenset(directories).intersection(ignore_dirs):
                    directories.remove(candidate)

                for name in files:
                    if name.endswith(suffix):
                        yield root / name


def dump_statistics(violations, /):
    for key, count in sorted(violations.stats.items(), key=operator.itemgetter(1)):
        print("{:4} - {}: {}".format(count, key, getattr(violations, key)[2]))

    print("\nFound {} errors.".format(sum(violations.stats.values())))


def dump_file(violations, quiet, path, /):
    def worker(content):
        for node in walk_module(quiet, content, filename):
            yield from check_node(node, violations)

    getter = operator.itemgetter(0)  # lineno
    filename = str(path)
    fmt = "{}:{{}}: [{{}}] {{}}".format(filename).format
    for lineno, code, msg in sorted(worker(path.read_bytes()), key=getter):
        if not quiet:
            print(fmt(lineno, code, msg))


def main():
    logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

    parser = argparse.ArgumentParser(description="Sphinx docstring checker")
    parser.add_argument(
        "files",
        nargs=argparse.ZERO_OR_MORE,
        default=[os.path.curdir],
        help="files or directories to check",
    )
    parser.add_argument(
        "--statistics",
        action="store_const",
        const=True,
        default=False,
        help="show counts for every rule with at least one violation",
    )
    # TODO: Reduce noise, python might dump some warnings to stderr (SyntaxWarning).
    parser.add_argument(
        "--quiet",
        action="store_const",
        const=True,
        default=False,
        help="print diagnostics, but nothing else",
    )
    parser.add_argument(
        "--ignore",
        nargs=argparse.ZERO_OR_MORE,
        default=[".venv", ".env"],
        help="directories to ignore",
    )
    parser.add_argument(
        "--enable",
        nargs=argparse.ZERO_OR_MORE,
        type=str.upper,
        default=[],
        help="Violation codes to enable (or ALL, to enable all)",
    )
    parser.add_argument(
        "--disable",
        nargs=argparse.ZERO_OR_MORE,
        type=str.upper,
        default=[],
        help="Violation codes to disable",
    )

    args = parser.parse_args()
    violations = Violations(enable=args.enable, disable=args.disable)
    for path in walk(args.files, args.ignore):
        dump_file(violations, args.quiet, path)

    if args.statistics and violations.stats:
        dump_statistics(violations)

    return 0 if not violations.stats else 1


if __name__ == "__main__":
    sys.exit(main())
