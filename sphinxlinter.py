# -*- coding: utf-8 -*-

import argparse
import ast
import collections
import importlib.metadata
import inspect
import itertools
import linecache
import logging
import operator
import os.path
import pathlib
import re
import sys
import typing
import warnings

try:
    import tomllib
except ImportError:
    # Python < 3.11, no tomllib available
    tomllib = None  # type: ignore

APP_NAME = "sphinx-linter"

# ============================================================================
# Default ignored directories for file discovery
# ============================================================================

# Ignore, at least, these directory basenames (default directories to ignore).
default_ignore_dirs = (
    # Common virtual environment directories
    "venv",
    "env",
    ".venv",
    ".env",
    # Common build directories
    ".git",  # Git
    ".hg",  # Mercurial
    ".pytest_cache",  # Pytest cache
    ".ruff_cache",  # Ruff cache
    "__pycache__",  # Python cache
)

# ============================================================================
# Docstring sections: https://www.sphinx-doc.org/en/master/usage/domains/python.html#info-field-lists
# ============================================================================
ptype_key = "type"
rtype_key = "rtype"
param_set = {"param", "parameter", "arg", "argument", "keyword", "key"}
return_set = {"return", "returns"}
raises_set = {"raises", "raise", "except", "exception"}

# Although Sphinx does not currently explain this distinction, its syntax was directly inherited from
# Epydoc (https://epydoc.sourceforge.net/manual-fields.html#variables), so it is generally understood that:
# - ivar: instance variable
# - cvar: class variable
# - var: variable (global or module-level variable)
class_var_set = {"ivar", "cvar"}
module_var_key = "var"
vartype_key = "vartype"
ignore_set = {"meta"}  # At this moment, it's ignored

# Sections that define types
types_set = {ptype_key, rtype_key, vartype_key}  # Sections that define types

# ============================================================================
# Regular expressions for parsing docstrings:
# ============================================================================
# Summary (everything before the first section or the end of the string)
summary_regex = re.compile(r'^(.*?)(?=^:|\Z)', flags=re.DOTALL | re.MULTILINE)
# Section (start with ':' and end before next ':' at start of line or end of string)
section_regex = re.compile(r'(^:.*?)(?=^:|\Z)', flags=re.DOTALL | re.MULTILINE)
# Trailing blank lines
trailing_regex = re.compile("(?:^\\s*$){2,}\\Z", flags=re.MULTILINE)
# Consecutive blank lines (not at end)
blank_lines_regex = re.compile("(?:^[ \t]*\r?\n){2,}(?=[^\r\n])", flags=re.MULTILINE)
# Docstring starting or ending with only quotes lines
quotes_starts_regex = re.compile(r'^"+\s*$')
quotes_ends_regex = re.compile(r'^\s*"+$')
# Leading whitespaces matcher: line starts with spaces/tabs followed by non-space
leading_ws_regex = re.compile('^[ \t]+\\S+')

# ----------------------------------
# Bad whitespace in section left-side:
# ----------------------------------
# - consecutive whitespace (anywhere)
# - leading/trailing whitespace (ignore break-line)
section_ws_left_err = re.compile('(\\s{2,}|^[ \t]+|[ \t]+$)').search

# ----------------------------------
# Bad whitespace in section right-side (type):
# ----------------------------------
# - missing leading whitespace (starts with non-space)
# - consecutive whitespace (anywhere)
# - trailing whitespace (ignore break-line)
section_ws_right_type_err = re.compile('(^\\S|\\s{2,}|[ \t]+$)').search

# ----------------------------------
# Bad whitespace in section right-side (description):
# ----------------------------------
# - missing leading whitespace (starts with non-space)
# - starts with 2+ whitespace (ignore break-line)
# - trailing whitespace (ignore break-line)
section_ws_right_desc_err = re.compile('(^\\S|^[ \t]{2,}|[ \t]+$)').search


class NodeTypes:
    FUNCTION = "function"
    CLASS = "class"
    MODULE = "module"


# ----------------------------------------------------------------------------
# Function definition parsed properties
# ----------------------------------------------------------------------------


class ParsedFuncParam(typing.NamedTuple):
    name: str
    order: int
    annotation: str | None


class ParsedFuncReturn(typing.NamedTuple):
    has_return: bool  # True if the function has a return or yield statement.
    annotation: str | None


class ParsedFuncDef(typing.NamedTuple):
    parameters: dict[str, ParsedFuncParam]
    returns: ParsedFuncReturn
    is_implemented: bool  # True if the function is implemented (not just a stub)


# ----------------------------------------------------------------------------
# Function docstring parsed properties
# ----------------------------------------------------------------------------

class ParsedDocsParam(typing.NamedTuple):
    section_key: str
    sep: bool  # True if ':' was present
    param_name: str | None
    param_type: str | None
    order: int  # Order of appearance in the docstring


class ParsedDocsVar(typing.NamedTuple):
    section_key: str
    sep: bool  # True if ':' was present
    var_name: str | None
    var_type: str | None  # Only for ´:vartype:´
    with_spaces: bool  # (True if var_name has spaces)
    description: str | None  # Only for ´:var:´, ´:ivar:´, ´:cvar:´
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
    kind: str  # NodeTypes.*
    summary: str | None  # The summary section (before the first section)
    params: list[ParsedDocsParam]
    returns: list[ParsedDocsReturn]
    raises: list[ParsedDocsRaise]
    variables: list[ParsedDocsVar]
    invalid: list[str]  # invalid section keys
    ignored: list[str]  # ignored section keys
    bad_whitespaces_def: list[str]  # section definitions with bad whitespaces

    rawdocs: str | None  # Raw docstring
    docs: str | None  # Cleaned docstring (inspect.cleandoc)
    docs_ini_lineno: int | None  # First line number of the docstring, None if no docstring
    docs_end_lineno: int | None  # End line number of the docstring, None if no docstring
    missing_blank_line_after: bool  # True if missing blank line after docstring
    non_blank_end_lines: bool  # True if there are non-blank lines after the last section


class Violations:
    # ----------------------------------------------------------------------------
    # Rules definition: Enabled | Code | Message
    # ----------------------------------------------------------------------------
    # DOC0xx: Docstring section issues
    # ----------------------------------------------------------------------------
    DOC001 = (True, "DOC001", "Invalid docstring section ({!r})")
    DOC002 = (True, "DOC002", "Malformed section ({!r})")
    DOC003 = (True, "DOC003", "Missing blank line after docstring")
    DOC004 = (True, "DOC004", "Missing blank line between summary and sections")
    DOC005 = (True, "DOC005", "Too many consecutive blank lines")
    DOC006 = (True, "DOC006", "Trailing empty lines")
    DOC007 = (True, "DOC007", "Misplaced section ({!r} appears after {!r})")
    # Ruff (missing-trailing-period) → enforces a trailing period on all docstring summaries (one-line and multi-line).
    # Rule (DOC008) → only enforces a trailing period on one-line docstrings, as recommended by PEP257.
    DOC008 = (True, "DOC008", "One-line docstring should end with a period")
    # Unlike Ruff D300 (triple-single-quotes),
    # this rule only checks that multi-line docstrings do not start or end with more than three double quotes.
    DOC009 = (True, "DOC009", "Docstring must not use more than 3 double quotes")

    DOC010 = (True, "DOC010", "Section definition contains invalid whitespace ({!r})")
    DOC011 = (True, "DOC011", "Trailing non-empty lines after last section")
    DOC012 = (True, "DOC012", "Leading whitespaces in first non-blank line ({!r})")
    # ----------------------------------------------------------------------------
    # DOC1xx: Parameter issues
    # ----------------------------------------------------------------------------
    DOC101 = (True, "DOC101", "Parameter documented but not in signature ({!r})")
    DOC102 = (True, "DOC102", "Invalid parameter type syntax ({!r})")
    DOC103 = (True, "DOC103", "Parameter type already in signature ({!r})")
    DOC104 = (True, "DOC104", "Parameter type mismatch with annotation ({!r} != {!r})")
    DOC105 = (True, "DOC105", "Duplicated parameter ({!r})")
    DOC106 = (True, "DOC106", "Parameter order mismatch with signature")
    DOC107 = (False, "DOC107", "Missing parameter in docstring ({!r})")  # Disabled by default
    # ----------------------------------------------------------------------------
    # DOC2xx: Return issues
    # ----------------------------------------------------------------------------
    DOC201 = (True, "DOC201", "Return documented but function has no return statement")
    DOC202 = (True, "DOC202", "Invalid return type syntax ({!r})")
    DOC203 = (True, "DOC203", "Return type already in signature ({!r})")
    DOC204 = (True, "DOC204", "Return type mismatch with annotation ({!r} != {!r})")
    DOC205 = (True, "DOC205", "Duplicated return section ({!r})")
    # ----------------------------------------------------------------------------
    # DOC3xx: Raises issues
    # ----------------------------------------------------------------------------
    DOC302 = (True, "DOC302", "Invalid exception type syntax ({!r})")
    DOC305 = (True, "DOC305", "Duplicated exception type ({!r})")
    # ----------------------------------------------------------------------------
    # DOC4xx: Variable issues
    # ----------------------------------------------------------------------------
    DOC402 = (True, "DOC402", "Invalid variable type syntax ({!r})")
    DOC403 = (True, "DOC403", "Variable name contains invalid whitespace ({!r})")
    DOC405 = (True, "DOC405", "Duplicated variable ({!r})")

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
    def validate_blank_lines(cls, parsed_docs, /):
        if parsed_docs.missing_blank_line_after:
            yield cls.DOC003, ()

        if text := parsed_docs.rawdocs:
            hits = blank_lines_regex.finditer(text)
            present = next(filter(None, hits), None)
            if present:
                yield cls.DOC005, ()

            hits = trailing_regex.finditer(text)
            present = next(filter(None, hits), None)
            if present:
                left, right = present.span()
                if left != right:
                    # finditer: Empty matches are included in the result.
                    yield cls.DOC006, ()

        if parsed_docs.non_blank_end_lines:
            yield cls.DOC011, ()

    @classmethod
    def validate_whitespaces(cls, parsed_docs, /):
        lines = parsed_docs.rawdocs.splitlines() if parsed_docs.rawdocs else []
        first = lines[0] if lines else ""
        # Check leading whitespaces in the first non-blank line:
        # - first line is not blank → use raw docstring first line ('parsed.docs' removed leading spaces)
        # - first line is blank → use cleaned docstring first line (to find the first non-blank line)
        if not first.strip() and parsed_docs.docs:
            lines = parsed_docs.docs.splitlines()
            first = lines[0] if lines else ""
        if first and leading_ws_regex.search(first):
            yield cls.DOC012, (first,)

        for section_def in parsed_docs.bad_whitespaces_def:
            yield cls.DOC010, (section_def,)

    @classmethod
    def validate_edge_quotes(cls, parsed_docs, /):
        text = parsed_docs.rawdocs
        if text:
            lines = text.splitlines()
            if len(lines) > 1 and (quotes_starts_regex.match(lines[0]) or quotes_ends_regex.match(lines[-1])):
                yield cls.DOC009, ()

    @classmethod
    def validate_summary(cls, parsed, /):
        if parsed.summary:
            summary_lines = parsed.summary.splitlines()
            br_tail_count = sum(1 for _ in itertools.takewhile(operator.not_, reversed(summary_lines)))
            has_sections = bool(parsed.params + parsed.returns + parsed.raises + parsed.invalid + parsed.ignored)
            if br_tail_count == 0 and has_sections:
                # Only applies if there are sections after the summary
                yield cls.DOC004, ()  # Missing blank line between summary and sections

            if not has_sections and len(summary_lines) == 1:
                line = summary_lines[0].rstrip()
                if line and not line.endswith('.'):
                    yield cls.DOC008, ()  # Summary should end with a period

    @classmethod
    def validate_params(cls, parsed_docs, parsed_params, /):
        """
        Validate the parameter sections of the parsed docstring against the function definition.

        :param parsed_docs: ParsedDocs parsed: Parsed docstring object.
        :param dict[str, ParsedFuncParam] parsed_params: Parsed function parameters.
        :return: Generator yielding violation tuples.
        """

        documented = list()  # Documented parameters, without duplicates and in order of appearance

        first_raises = min(parsed_docs.raises, key=cls._get_order, default=None)
        first_return = min(parsed_docs.returns, key=cls._get_order, default=None)

        for param in parsed_docs.params:
            section_key, sep, name, kind, order = param

            param_props = parsed_params.get(name)
            type_hint = param_props.annotation if param_props else None

            # Malformed: missing sep/name/type(when required)
            if not (sep and name) or (section_key == ptype_key and not kind):
                yield cls.DOC002, (section_key,)
            if name and name not in parsed_params:  # Documented but not in signature
                yield cls.DOC101, (name,)
            if kind and not cls.is_valid_type_hint(kind):  # Invalid type syntax
                yield cls.DOC102, (kind,)
            if kind and type_hint and kind == type_hint:  # Redundant type
                yield cls.DOC103, (kind,)
            if kind and type_hint and kind != type_hint:  # Mismatched type
                yield cls.DOC104, (kind, type_hint)

            if name and name in documented:  # Duplicated parameter
                yield cls.DOC105, (name,)

            if first_raises and order > first_raises.order:
                # Params after raises are considered misplaced
                yield cls.DOC007, (section_key, first_raises.section_key,)
            if first_return and order > first_return.order:
                # Params after returns are considered misplaced
                yield cls.DOC007, (section_key, first_return.section_key,)

            if name and name not in documented:
                documented.append(name)

        # Check parameter order ignoring missing/extra parameters
        orderby = operator.attrgetter("order")
        # Ignore parameters not documented
        defined_documented = (n.name for n in sorted(parsed_params.values(), key=orderby) if n.name in documented)
        # Ignore documented parameters not in the function definition
        documented_defined = (n for n in documented if n in parsed_params)
        if tuple(defined_documented) != tuple(documented_defined):
            yield cls.DOC106, ()

        # Check for missing parameter keys in docstring
        ignored = frozenset(("self", "cls", "args", "kwargs"))  # Common ignored parameter names
        if documented:
            # Only check for missing parameters if there is at least one documented parameter
            missing = sorted((parsed_params.keys() - ignored) - frozenset(documented))
            for name in missing:
                yield cls.DOC107, (name,)

    @classmethod
    def validate_return(cls, parsed_docs, parsed_return, is_implemented, /):
        """
        Validate the return sections of the parsed docstring.

        :param ParsedDocs parsed_docs: Parsed docstring object.
        :param ParsedFuncReturn parsed_return: Parsed function return properties.
        :param bool is_implemented: True if the function is implemented (not just a stub).
        :return: Generator yielding violation tuples.
        """

        sign_return_type = parsed_return.annotation
        if parsed_docs.returns and (not parsed_return.has_return and is_implemented):
            yield cls.DOC201, ()  # Return documented but implementation has no return

        bag = set()
        for doc_returns in parsed_docs.returns:
            section_key, sep, doc_return_type, description, section_key_ctx, order = doc_returns

            # Malformed: missing sep/type/description(when required) or invalid context
            if not sep or section_key_ctx:
                # Missing sep or invalid context (section_key_ctx is True)
                yield cls.DOC002, (section_key,)
            elif section_key in return_set and not description:
                # ´:return:´ without description
                yield cls.DOC002, (section_key,)
            elif section_key == rtype_key and not doc_return_type:  # ´:rtype:´ without type
                yield cls.DOC002, (section_key,)

            # Invalid or redundant return type checks
            if doc_return_type and not cls.is_valid_type_hint(doc_return_type):  # Invalid return type
                yield cls.DOC202, (doc_return_type,)
            if doc_return_type and sign_return_type and doc_return_type == sign_return_type:  # Redundant return type
                yield cls.DOC203, (doc_return_type,)
            if doc_return_type and sign_return_type and doc_return_type != sign_return_type:  # Mismatched return type
                yield cls.DOC204, (doc_return_type, sign_return_type)
            # Duplicate return section
            if section_key in bag:
                yield cls.DOC205, (section_key,)  # Duplicate return section

            if section_key in return_set:
                bag.update(return_set)  # Mark all return section as used to avoid duplicates (:return: & :returns:)
            else:
                bag.add(section_key)

    @classmethod
    def validate_raises(cls, parsed_docs, /):
        """Validate the raises sections of the parsed docstring."""

        bag = set()
        first_return = min(parsed_docs.returns, key=cls._get_order, default=None)

        for section_key, sep, error_types, order in parsed_docs.raises:
            if not (sep and error_types):  # Missing sep/error types
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
    def validate_variables(cls, parsed_docs, /):
        """Validate the variable sections of the parsed docstring."""

        bag = set()
        for var in parsed_docs.variables:
            section_key, sep, name, kind, with_spaces, description, order = var
            missing_desc = section_key in class_var_set and not description
            missing_type = section_key == vartype_key and not kind

            # Malformed: missing sep/name/description(when required)/type(when required)
            if not (sep and name) or missing_type or missing_desc:
                yield cls.DOC002, (section_key,)
            if kind and not cls.is_valid_type_hint(kind):  # Invalid type syntax
                yield cls.DOC402, (kind,)
            if with_spaces:  # Variable name contains spaces
                yield cls.DOC403, (name,)
            if name and (section_key, name) in bag:  # Duplicated variable in the same section
                yield cls.DOC405, (name,)

            if name:
                bag.add((section_key, name))

    @classmethod
    def discover_all(cls, parsed_docs, parsed_func, /):
        yield from ((cls.DOC001, (section_key,)) for section_key in parsed_docs.invalid)
        yield from cls.validate_blank_lines(parsed_docs)
        yield from cls.validate_whitespaces(parsed_docs)
        yield from cls.validate_edge_quotes(parsed_docs)
        yield from cls.validate_summary(parsed_docs)

        if parsed_docs.kind == NodeTypes.FUNCTION:  # Only functions have parameters, returns, and raises
            yield from cls.validate_params(parsed_docs, parsed_func.parameters)
            yield from cls.validate_return(parsed_docs, parsed_func.returns, parsed_func.is_implemented)
            yield from cls.validate_raises(parsed_docs)
        elif parsed_docs.kind in (NodeTypes.CLASS, NodeTypes.MODULE):  # Only classes and modules have variables
            yield from cls.validate_variables(parsed_docs)

    def discover(self, parsed_docs, parsed_func, /):
        for (_, code, msg), ctx in self.discover_all(parsed_docs, parsed_func):
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


def fetch_var_name(parts_a, /):
    if len(parts_a) == 1:
        var_name = None
    else:
        var_name = " ".join(parts_a[1:])
    with_spaces = len(parts_a) > 2
    return (var_name, with_spaces)


def parse_section_var(section_key, sep, parts_a, parts_b, order, /):
    var_type = None
    var_name, with_spaces = fetch_var_name(parts_a)
    if parts_b:  # ´:var [VarName]: [Description]´
        description = " ".join(parts_b)
    else:  # ´:var [VarName]:´ (without description)
        description = None
    return ParsedDocsVar(section_key, sep, var_name, var_type, with_spaces, description, order)


def parse_section_vartype(section_key, sep, parts_a, parts_b, order, /):
    var_name, with_spaces = fetch_var_name(parts_a)
    if parts_b:  # ´:vartype [VarName]: [VarType]´
        var_type = " ".join(parts_b)
    else:  # ´:vartype [VarName]:´ (without type)
        var_type = None
    return ParsedDocsVar(section_key, sep, var_name, var_type, with_spaces, None, order)


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
        yield from (chunk for match in section_regex.finditer(docstring) if (chunk := match.group()))


def get_summary(docstring, /):
    if docstring and (match := summary_regex.match(docstring)):
        return match.group()
    else:
        return None


def get_node_type(node, /):
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        kind = NodeTypes.FUNCTION
    elif isinstance(node, ast.ClassDef):
        kind = NodeTypes.CLASS
    elif isinstance(node, ast.Module):
        kind = NodeTypes.MODULE
    else:
        raise ValueError
    return kind


def fetch_bad_ws_definitions(section, section_key, sep, a_raw, b_raw, /):
    """
    Yields the parts of the section definition that have bad whitespaces.

    :param str section: Full section text.
    :param str section_key: Section key (first word of part before ':').
    :param bool sep: True if ':' was present.
    :param str a_raw: Part before the first ':'
    :param str b_raw: Part after the first ':'

    :return: Generator yielding section definitions with bad whitespaces.
    """

    if section_key in types_set:
        if section_ws_left_err(a_raw) or section_ws_right_type_err(b_raw):  # Check left-side and right-side type
            yield section

    elif section_ws_left_err(a_raw):
        # Reconstruct section definition with only left-side
        yield ":{}{}".format(a_raw, ":" if sep else "")

    elif section_ws_right_desc_err(b_raw):  # Check right-side description
        yield section


def parse_docs(node, filename, /):
    params = list()
    raises = list()
    returns = list()
    variables = list()

    # Does not use 'set' to preserve the order of appearance
    invalid = list()
    ignored = list()
    bad_whitespaces_def = list()  # List of section definitions with bad whitespaces

    rawdocs = ast.get_docstring(node, clean=False)
    docs = rawdocs if rawdocs is None else inspect.cleandoc(rawdocs)

    kind = get_node_type(node)
    is_func = kind == NodeTypes.FUNCTION
    is_class = kind == NodeTypes.CLASS
    is_module = kind == NodeTypes.MODULE

    section_key, b_raw = (None, None)  # Initialize for misplaced_tail_text check
    for order, section in enumerate(itersections(docs)):
        a_raw, sep, b_raw = section.lstrip(":").partition(":")
        sep = bool(sep)  # True if ':' was present
        b = b.splitlines()[0].strip() if (b := b_raw.strip()) else ""  # Only first line of description is relevant.

        parts_a = a_raw.split()
        parts_b = b.split()
        section_key = parts_a[0].lower()

        # Check for bad whitespaces in section definition
        bad_whitespaces_def.extend(fetch_bad_ws_definitions(section, section_key, sep, a_raw, b_raw))

        if is_func and section_key in param_set:
            params.append(parse_section_param(section_key, sep, parts_a, order))

        elif is_func and section_key == ptype_key:
            params.append(parse_section_type(section_key, sep, parts_a, parts_b, order))
        elif is_func and section_key in rtype_key:
            returns.append(parse_section_rtype(section_key, sep, parts_a, parts_b, order))
        elif is_func and section_key in raises_set:
            raises.append(parse_section_raise(section_key, sep, parts_a, order))
        elif is_func and section_key in return_set:
            returns.append(parse_section_return(section_key, sep, parts_a, parts_b, order))
        elif (is_class and section_key in class_var_set) or (is_module and section_key == module_var_key):
            variables.append(parse_section_var(section_key, sep, parts_a, parts_b, order))
        elif (is_class or is_module) and section_key == vartype_key:
            variables.append(parse_section_vartype(section_key, sep, parts_a, parts_b, order))
        elif section_key in ignore_set:
            if section_key not in ignored:
                ignored.append(section_key)
        elif section_key not in invalid:
            invalid.append(section_key)

    non_blank_end_lines = False
    if section_key in types_set and len(b_raw.splitlines()) > 1:
        # Check for non-blank lines after the last section. (Only for type sections that cannot have a description)
        non_blank_end_lines = any(line.strip() for line in b_raw.splitlines()[1:])  # Non-empty lines

    if docs:
        summary = get_summary(docs)
        first = node.body[0]
        docs_ini_lineno, docs_end_lineno = (first.lineno, first.end_lineno)
    else:
        summary = None
        docs_ini_lineno = docs_end_lineno = None

    if docs_end_lineno:
        after_lineno = docs_end_lineno + 1
        # Use linecache instead of ast to get the next line after the docstring correctly, because ast skips comments.
        after_line = linecache.getline(filename, after_lineno)
        missing_blank_line_after = bool(after_line.strip())  # True if the line is not blank
    else:
        missing_blank_line_after = False

    return ParsedDocs(
        kind=kind,
        summary=summary,
        rawdocs=rawdocs,
        docs=docs,
        docs_ini_lineno=docs_ini_lineno,
        docs_end_lineno=docs_end_lineno,
        params=params,
        returns=returns,
        raises=raises,
        variables=variables,
        invalid=invalid,
        ignored=ignored,
        bad_whitespaces_def=bad_whitespaces_def,
        missing_blank_line_after=missing_blank_line_after,
        non_blank_end_lines=non_blank_end_lines,
    )


def has_return_or_yield(node, /):
    """
    Returns True if the given AST node (ast.FunctionDef or ast.AsyncFunctionDef)
    contains a 'return', 'yield', or 'yield from' statement in its main body
    (excluding nested functions).

    :param ast.AST node: Root node to explore.
    :return: Whether the function has either "return" or "yield".
    :rtype: bool
    """

    class ReturnYieldVisitor(ast.NodeVisitor):
        def __init__(self, /):
            self.found = False
            self.depth = 0

        def visit_nested(self, node_, /):
            if self.depth == 0:
                self.depth += 1
                self.generic_visit(node_)
                self.depth -= 1

        def visit_FunctionDef(self, node_, /):
            self.visit_nested(node_)

        def visit_AsyncFunctionDef(self, node_, /):
            self.visit_nested(node_)

        def visit_Return(self, node_, /):
            self.found = True

        def visit_Yield(self, node_, /):
            self.found = True

        def visit_YieldFrom(self, node_, /):
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

    :param ast.AST node: Root node to explore.
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
            if isinstance(exc, ast.Call) and isinstance(exc.func, ast.Name) and exc.func.id == error_name:
                return True

            else:  # Case: "raise NotImplementedError"
                return isinstance(exc, ast.Name) and exc.id == error_name

        elif isinstance(stmt, ast.Expr):  # Case: "..."
            return isinstance(stmt.value, ast.Constant) and (stmt.value.value is Ellipsis)
        else:
            return False


def get_args(node, /):
    """Yield function parameters in the exact order defined by Python's function signature grammar."""

    yield from node.args.posonlyargs  # Positional-only args
    yield from node.args.args  # Regular args
    if vararg := node.args.vararg:  # Var positional arg (*args)
        yield vararg
    yield from node.args.kwonlyargs  # Keyword-only args
    if kwarg := node.args.kwarg:  # Var keyword arg (**kwargs)
        yield kwarg


def get_params_props(node, /):
    """Returns an iterator with each function parameter's properties."""

    for order, arg in enumerate(get_args(node)):
        annotation = ast.unparse(ann) if (ann := arg.annotation) else None
        yield (arg.arg, ParsedFuncParam(arg.arg, order, annotation))


def get_return_props(node, has_returns, /):
    """Fetches the function return properties."""

    annotation = ast.unparse(node.returns) if node.returns else None
    return ParsedFuncReturn(has_returns, annotation)


def check_node(node, violations, filename, /):
    for lineno, code, msg, ctx in checker(node, violations, filename):
        yield (lineno, code, msg.format(*ctx))


def checker(node, violations, filename, /):
    """
    Explore the given AST node and yield each violation found.

    :param ast.AST node: Root node to explore.
    :param Violations violations: Violations instance with enabled/disabled rules.
    :param str filename: Filename to check.

    :return: Generator with data of each violation.
    :rtype: typing.Iterator[tuple[int, str, dict]]
    """

    parsed_docs = parse_docs(node, filename)
    lineno = parsed_docs.docs_ini_lineno

    if parsed_docs.kind == NodeTypes.FUNCTION:
        func_params_props = dict(get_params_props(node))
        func_return_props = get_return_props(node, has_return_or_yield(node))
        func_is_implemented = not is_not_implemented(node, rawdocs=parsed_docs.rawdocs)
        parsed_func = ParsedFuncDef(func_params_props, func_return_props, func_is_implemented)
    else:  # ClassDef or Module
        parsed_func = None

    for (code, msg), ctx in violations.discover(parsed_docs, parsed_func):
        yield (lineno, code, msg, ctx)


def walk_module(quiet, data, filename, /):
    """
    Yields each function node from the parsed "data" tree.

    :param bool quiet: If False, print warnings to stderr.
    :param bytes data: Content to parse.
    :param str filename: File name to use when printing messages.

    :return: Each root node of every function/method.
    :rtype: Iterator[ast.AST]
    """

    try:
        tree = ast.parse(data, filename=filename)
    except SyntaxError as e:
        if not quiet:
            logging.warning("%s: %s", filename, e)
    else:
        klasses = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Module)
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
            yield from check_node(node, violations, filename)

    getter = operator.itemgetter(0)  # lineno
    filename = str(path)
    fmt = "{}:{{}}: [{{}}] {{}}".format(filename).format
    for lineno, code, msg in sorted(worker(path.read_bytes()), key=getter):
        if not quiet:
            print(fmt(lineno, code, msg))


def dump_version():
    path = pathlib.Path(__file__).with_name("pyproject.toml")
    if tomllib and path.exists():  # standalone script
        with path.open("rb") as f:
            version = tomllib.load(f)["project"]["version"]
    else:  # installed package
        try:
            version = importlib.metadata.version(APP_NAME)
        except importlib.metadata.PackageNotFoundError:
            version = "unknown"
    print("{} {}".format(APP_NAME, version))


def get_config_start_dir(paths, /):
    resolve = (pathlib.Path(p).resolve() for p in paths)
    parents = map(str, ((p.parent if p.is_file() else p) for p in resolve))
    return os.path.commonpath(parents)


def load_config(config_file, check_files, /):
    """
    Load configuration from 'pyproject.toml' if available.

    If 'config_file' is provided, it is used directly.
    Otherwise, search upward from the common ancestor of 'check_files' for 'pyproject.toml'

    :param str | None config_file: Path to 'pyproject.toml' file.
    :param list[str] check_files: List of files/directories to check.
    :rtype: dict
    """

    config = dict()

    if not tomllib:
        msg = "tomllib not available; config files cannot be loaded. Please use Python 3.11+ to enable this feature."
        logging.warning(msg)
        return config

    if config_file:
        paths = (pathlib.Path(config_file),)
    else:
        dirpath = pathlib.Path(get_config_start_dir(check_files))
        parents = (dirpath, *dirpath.parents)
        paths = (p for parent in parents if (p := (parent / "pyproject.toml")) and p.exists())

    for path in paths:
        try:
            data = tomllib.loads(path.read_text(encoding="utf-8"))
        except (tomllib.TOMLDecodeError, PermissionError):
            continue  # Invalid TOML or inaccessible file, skip it
        else:
            if "tool" in data and APP_NAME in data["tool"]:
                # Only use if it has [tool.sphinx-linter] section
                config = data["tool"][APP_NAME]
                break
    return config


def main():
    logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

    parser = argparse.ArgumentParser(description="Sphinx docstring checker")
    parser.add_argument(
        "files",
        nargs=argparse.ZERO_OR_MORE,
        default=[os.path.curdir],
        help="Files or directories to check",
    )
    parser.add_argument(
        "--statistics",
        action="store_const",
        const=True,
        default=False,
        help="Show counts for every rule with at least one violation",
    )
    parser.add_argument(
        "--quiet",
        action="store_const",
        const=True,
        default=False,
        help="Print diagnostics, but nothing else",
    )
    parser.add_argument(
        "--ignore",
        nargs=argparse.ZERO_OR_MORE,
        default=[],
        help="Directories to ignore. Defaults to: ({})".format(", ".join(default_ignore_dirs)),
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
    parser.add_argument(
        "--version",
        action="store_const",
        const=True,
        default=False,
        help="Print version and exit",
    )
    parser.add_argument(
        "--config",
        type=str,
        default=None,
        help=(
            "Path to 'pyproject.toml' configuration file. "
            "If not provided, search upward from the files’ common ancestor for 'pyproject.toml'"
        ),
    )
    parser.add_argument(
        "--isolated",
        action="store_const",
        const=True,
        default=False,
        help="Run in isolated mode, ignoring configuration files",
    )

    # Disable SyntaxWarnings to reduce output noise from python parser
    #   for example: SyntaxWarning: invalid escape sequence
    warnings.simplefilter("ignore", SyntaxWarning)
    args = parser.parse_args()

    if args.version:
        dump_version()
        return 0

    config = dict() if args.isolated else load_config(args.config, args.files)
    # CLI Arguments have precedence over config file settings
    enable = args.enable or config.get("enable", [])
    disable = args.disable or config.get("disable", [])
    ignore = args.ignore or config.get("ignore", default_ignore_dirs)

    violations = Violations(enable=enable, disable=disable)
    for path in walk(args.files, ignore):
        dump_file(violations, args.quiet, path)

    if args.statistics and violations.stats:
        dump_statistics(violations)

    if not args.quiet and not violations.stats:
        print("All checks passed!")

    return 0 if not violations.stats else 1


if __name__ == "__main__":
    sys.exit(main())
