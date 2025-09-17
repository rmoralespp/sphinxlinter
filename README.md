# sphinxlinter

[![pypi](https://img.shields.io/pypi/v/sphinx-linter.svg)](https://pypi.python.org/pypi/sphinx-linter)
[![CI](https://github.com/rmoralespp/sphinxlinter/workflows/CI/badge.svg)](https://github.com/rmoralespp/sphinxlinter/actions?query=event%3Arelease+workflow%3ACI)
[![codecov](https://codecov.io/gh/rmoralespp/sphinxlinter/branch/main/graph/badge.svg)](https://app.codecov.io/gh/rmoralespp/sphinxlinter)
[![license](https://img.shields.io/github/license/rmoralespp/sphinxlinter.svg)](https://github.com/rmoralespp/sphinxlinter/blob/main/LICENSE)

A lightweight Python linter for checking Sphinx docstrings and ensuring they follow the recommended field list style
and are consistent with function signatures.

In general, a typical Sphinx docstring has the following
format ([ref](https://sphinx-rtd-tutorial.readthedocs.io/en/latest/docstrings.html)):

```
"""[Summary]

:param [ParamType] [ParamName]: [ParamDescription]
:type [ParamName]: 
...
:raises [ErrorType]: [ErrorDescription]
...
:return: [ReturnDescription]
:rtype: [ReturnType]
"""
```

Requirements

- Python 3.8+

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

## Optional arguments

* **--help:** Show help message and exit
* **--enable:** Whitespace-separated list of violation codes to enable (or ALL, to enable all), by default all are enabled.
* **--disable:** Whitespace-separated list of violation codes to disable, by default none are disabled. **Takes precedence over --enable**
* **--ignore:** Directories to ignore from analysis

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

**DOC0xx: Docstring section issues**

| Code   | Description                                     |
|--------|-------------------------------------------------|
| DOC001 | Unknown docstring section                       |
| DOC002 | Malformed section                               |
| DOC003 | Missing blank line after docstring              |
| DOC004 | Missing blank line between summary and sections |
| DOC005 | Too many consecutive empty lines                |
| DOC006 | Trailing empty lines                            |

**DOC1xx: Parameter issues**

| Code   | Description                               |
|--------|-------------------------------------------|
| DOC101 | Parameter documented but not in signature |
| DOC102 | Invalid parameter type syntax             |
| DOC103 | Parameter type already in signature       |
| DOC104 | Parameter type mismatch with hint         |
| DOC105 | Duplicated parameter                      |

**DOC2xx: Return issues**

| Code   | Description                                  |
|--------|----------------------------------------------|
| DOC201 | Return documented but function has no return |
| DOC202 | Invalid return type syntax                   |
| DOC203 | Return type already in signature             |
| DOC204 | Return type mismatch with annotation         |
| DOC205 | Duplicated return section                    |

**DOC3xx: Raises issues**

| Code   | Description                   |
|--------|-------------------------------|
| DOC302 | Invalid exception type syntax |
| DOC305 | Duplicated exception type     |

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