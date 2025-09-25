# sphinxlinter

[![pypi](https://img.shields.io/pypi/v/sphinx-linter.svg)](https://pypi.python.org/pypi/sphinx-linter)
[![CI](https://github.com/rmoralespp/sphinxlinter/workflows/CI/badge.svg)](https://github.com/rmoralespp/sphinxlinter/actions?query=event%3Arelease+workflow%3ACI)
[![codecov](https://codecov.io/gh/rmoralespp/sphinxlinter/branch/main/graph/badge.svg)](https://app.codecov.io/gh/rmoralespp/sphinxlinter)
[![license](https://img.shields.io/github/license/rmoralespp/sphinxlinter.svg)](https://github.com/rmoralespp/sphinxlinter/blob/main/LICENSE)

A lightweight Python linter that ensures **Sphinx docstrings** follow the
recommended [field list style](https://www.sphinx-doc.org/en/master/usage/domains/python.html#info-field-lists)
and are consistent with function signatures and implementation.

**Motivation**

This linter enforces Sphinx docstring rules—like field list style and consistency with function signatures and
implementation—not covered
by [pydocstyle](https://www.pydocstyle.org/en/stable/error_codes.html), [pydoclint](https://jsh9.github.io/pydoclint/violation_codes.html),
or [ruff](https://docs.astral.sh/ruff/rules/).

In general, a typical Sphinx docstring has the following
format ([ref](https://sphinx-rtd-tutorial.readthedocs.io/en/latest/docstrings.html)):

```
"""[Summary]

:param [ParamType] [ParamName]: [ParamDescription]
:type [ParamName]: [ParamType] 
...
:raises [ErrorType]: [ErrorDescription]
...
:return: [ReturnDescription]
:rtype: [ReturnType]
"""
```

Requirements

- Python 3.9+

Quick usage, download the `sphinxlinter.py` script from
following [link](https://github.com/rmoralespp/sphinxlinter/archive/refs/heads/main.zip)
and run it with Python:

Run on current working directory

```bash
python sphinxlinter.py
```

Pass one or more files or directories. Directories are searched recursively for `*.py`, ignoring common virtualenv/cache
folders.

```bash
python sphinxlinter.py path/to/file.py path/to/package_dir
```

## Installation

To install **sphinxlinter** using `pip`, run the following command:

```bash
pip install sphinx-linter
```

## Usage from command line (CLI) if installed

Run on current working directory

```bash
sphinxlinter
```

Run on specific files or directories

```bash
sphinxlinter path/to/file_or_dir ...
```

## Arguments and Options

**Arguments**

* `[FILES]`: List of files or directories to check.

**Options**

* `--help`: Displays the help message and exits.
* `--enable`:  Violation codes to enable (or ALL, to enable all rules), by default all are enabled.
* `--disable`: Violation codes to disable, by default none are disabled. **Takes precedence over `--enable`**.
* `--ignore`: Directories to exclude from analysis (for example `venv`, `.cache`).
* `--statistics`: Show counts for every rule with at least one violation.
* `--quiet`: Suppresses all output except the statistics summary if `--statistics` is also set.

## Violation reporting

Example output

```text
/path/to/module.py:42: [DOC102] Invalid parameter type syntax ('List[int]')
/path/to/module.py:10: [DOC101] Parameter documented but not in signature ('unused_param')
```

Format: `filename:line: [CODE] message`

Common violation codes:

- `DOC0xx`: Docstring section issues
- `DOC1xx`: Parameter issues
- `DOC2xx`: Return issues
- `DOC3xx`: Raises issues

How it works (brief)

- Parses Python AST to find `FunctionDef` members.
- Extracts signatures and docstring
  sections [Sphinx field lists](https://www.sphinx-doc.org/en/master/usage/domains/python.html#info-field-lists).
- Validates section presence, syntax and consistency with type annotations.

Notes

- The tool prints findings to stdout and does not modify files.
- To integrate into CI, run the script and treat any stdout lines as failures in your pipeline logic.

### Violation Codes Table

### DOC0xx: Docstring section issues

| Code   | Description                                     | Justification                                              |
|--------|-------------------------------------------------|------------------------------------------------------------|
| DOC001 | Unknown docstring section                       | Detects sections not recognized by Sphinx conventions.     |
| DOC002 | Malformed section                               | Ensures sections follow correct Sphinx formatting.         |
| DOC003 | Missing blank line after docstring              | Improves readability and separates docstrings from code.   |
| DOC004 | Missing blank line between summary and sections | Maintains clarity and standard docstring structure.        |
| DOC005 | Too many consecutive empty lines                | Avoids unnecessary whitespace, keeping docstrings clean.   |
| DOC006 | Trailing empty lines                            | Ensures docstrings do not contain superfluous blank lines. |
| DOC007 | Misplaced section                               | Ensures docstrings sections are correctly located.         |

### DOC1xx: Parameter issues

| Code   | Description                               | Justification                                                         |
|--------|-------------------------------------------|-----------------------------------------------------------------------|
| DOC101 | Parameter documented but not in signature | Detects inconsistencies between documentation and function signature. |
| DOC102 | Invalid parameter type syntax             | Ensures parameter types conform to valid Python type hint syntax.     |
| DOC103 | Parameter type already in signature       | Prevents redundant type declarations.                                 |
| DOC104 | Parameter type mismatch with hint         | Ensures documented types match actual function hints.                 |
| DOC105 | Duplicated parameter                      | Avoids repeating the same parameter in the docstring.                 |

### DOC2xx: Return issues

| Code   | Description                                  | Justification                                                             |
|--------|----------------------------------------------|---------------------------------------------------------------------------|
| DOC201 | Return documented but function has no return | Indicates that it is documented for returns, but has no return statement. |
| DOC202 | Invalid return type syntax                   | Ensures return type conform to valid Python type hint syntax.             |
| DOC203 | Return type already in signature             | Prevents redundant return type hints.                                     |
| DOC204 | Return type mismatch with annotation         | Validates consistency with function return type hints.                    |
| DOC205 | Duplicated return section                    | Avoids repeated return sections in then docstring.                        |

### DOC3xx: Raises issues

| Code   | Description                   | Justification                                       |
|--------|-------------------------------|-----------------------------------------------------|
| DOC302 | Invalid exception type syntax | Ensures exceptions conform to valid Python syntax.  |
| DOC305 | Duplicated exception type     | Prevents repetition of exceptions in the docstring. |

## Development

To contribute to the project, you can run the following commands for testing and documentation:

First, ensure you have the latest version of `pip`:

```python -m pip install --upgrade pip```

### Running Unit Tests

Install the development dependencies and run the tests:

```
pip install --group=test  # Install test dependencies
pytest tests/ # Run all tests
pytest --cov sphinxlinter # Run tests with coverage
```

### Running Linter

```
pip install --group=lint  # Install linter dependencies
ruff check . # Run linter
```

## License

This project is licensed under the [MIT license](LICENSE).