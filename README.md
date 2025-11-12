# sphinxlinter

[![GitHub tag](https://img.shields.io/github/tag/rmoralespp/sphinxlinter?include_prereleases=&sort=semver&color=black)](https://github.com/rmoralespp/sphinxlinter/releases/)
[![PyPI](https://img.shields.io/pypi/v/sphinx-linter.svg)](https://pypi.python.org/pypi/sphinx-linter)
[![CI](https://github.com/rmoralespp/sphinxlinter/workflows/CI/badge.svg)](https://github.com/rmoralespp/sphinxlinter/actions?query=event%3Arelease+workflow%3ACI)
[![codecov](https://codecov.io/gh/rmoralespp/sphinxlinter/branch/main/graph/badge.svg)](https://app.codecov.io/gh/rmoralespp/sphinxlinter)
[![License](https://img.shields.io/github/license/rmoralespp/sphinxlinter.svg)](https://github.com/rmoralespp/sphinxlinter/blob/main/LICENSE)

A lightweight Python linter for **Sphinx-style docstrings**.  
It validates structure, field consistency, and alignment between documentation and code.

---

## Overview

Sphinx-style docstrings are widely used across Python projects, but existing tools such as
[pydocstyle](https://www.pydocstyle.org), [pydoclint](https://jsh9.github.io/pydoclint/),
and [ruff](https://docs.astral.sh/ruff/) focus primarily on general docstring formatting,
[PEP257](https://peps.python.org/pep-0257) compliance,
and style enforcement.

It is designed to **complement**, not overlap with, these tools.  
It targets **Sphinx-specific field list conventions** and performs **semantic consistency checks**
that go beyond what other linters cover.

Specifically, it focuses on:

- 🧩 Enforces
  [Sphinx-style field list](https://www.sphinx-doc.org/en/master/usage/domains/python.html#info-field-lists) formatting
- 🛠️ Ensures **consistency** between docstrings, signatures, and implementation
- 📐 Validates **section order, duplication, and syntax of documented types and errors**
- 📊 Generates concise, **CI-friendly** reports
- ⚙️ Provides a **minimalist CLI** for easy workflow integration
- 🐍 Uses only the **Python standard library** for full compatibility
- 🧼 Promotes **clean, maintainable documentation**

---

## 📦 Installation

Requires **Python ≥ 3.9**, but **Python ≥ 3.11** is recommended to allow loading configuration files with
`tomlib` from the standard library.

To install via `pip`, run:

```bash
pip install sphinx-linter
```

---

## ⚡ Quick Start

### CLI Tool

After installation via `pip`, you can run the `sphinxlinter` command directly from your terminal.

**Run on the current directory:**

- Run in the current directory: `sphinxlinter .`
- Or use the short alias: `spxl .`

**Run on specific files or directories:**

```bash
spxl path/to/file.py path/to/package/
```

> [!NOTE]
>
> Directories are scanned recursively for `.py` files, ignoring virtual environments and cache folders.

### Standalone Script

Alternatively, you can download the standalone script by clicking the
following [link](https://github.com/rmoralespp/sphinxlinter/archive/refs/heads/main.zip) and run it with Python:

```bash
python sphinxlinter.py path/to/source/
```

---

## Command Line Usage

| Argument / Option | Description                                                                             |
|-------------------|-----------------------------------------------------------------------------------------|
| `[FILES]`         | Files or directories to lint.                                                           |
| `--help`          | Show help message and exit.                                                             |
| `--enable`        | Enable specific rule codes (or `ALL`).                                                  |
| `--disable`       | Disable specific rule codes (overrides `--enable`).                                     |
| `--ignore`        | Exclude directories (e.g. `venv`, `.cache`).                                            |
| `--statistics`    | Show per-rule violation counts.                                                         |
| `--quiet`         | Print diagnostics, but nothing else                                                     |
| `--version`       | Print version and exit                                                                  |
| `--config`        | If not provided, search upward from the `[FILES]`’ common ancestor for `pyproject.toml` |
| `--isolated `     | Run in isolated mode, ignoring configuration files                                      |

---

## Setting Configuration

Configuration is done via `pyproject.toml`.
The configuration section is `[tool.sphinx-linter]`.

### Configuration File Location

The linter uses `--config` to specify a configuration file. If this option is not provided, it searches for a
configuration file starting at the common ancestor of all specified files/directories, moving upward until it finds one
or reaches the filesystem root.
If no configuration file is found, the linter runs with its default settings.

> [!NOTE]
> **Ignores search configuration files that meet any of the following conditions:**
>
> - Malformed `pyproject.toml` is detected.
> - No `[tool.sphinx-linter]` section is found.
> - Permissions prevent reading the file.
>
> **Also ignored if:**
> - The `--isolated` flag is set.
> - A specific configuration file is provided via `--config`.
> - Python version is below 3.11 (no `tomllib` support).


**Example configuration:**

```toml
[tool.sphinx-linter]
# Enable all rules, alternatively specify individual rule codes
enable = ["ALL"]
# Disable specific rules, taking precedence over enable
disable = ["DOC003", "DOC101"]
# Ignore specific directories from linting
ignore = ["venv", ".cache"]
```

> [!NOTE]
>
> Can also be set via CLI options `--enable`, `--disable`, and `--ignore`.
>
> If both CLI options and configuration file are provided, **CLI options take precedence**.

---

## Output Format

When violations are found, the tool outputs lines in the following format:

```text
path/to/file.py:LINE-NUMBER: [CODE] Description of the violation.
```

> [!TIP]
>
> Use `--quiet` to suppress output except for statistics summary if `--statistics` is also set.

> [!NOTE]
>
> * Exit code `0` means no violations were found; exit code `1` indicates that violations were detected.
> * The tool never modifies source files.

**Categories:**

- `DOC0xx`: Structure and formatting issues
- `DOC1xx`: Parameter issues
- `DOC2xx`: Return issues
- `DOC3xx`: Raises issues
- `DOC4xx`: Variable issues

---

## Violation Codes

### DOC0xx — Structure

| Code   | Description                                      | Purpose                                                                         | Enabled by Default |
|--------|--------------------------------------------------|---------------------------------------------------------------------------------|--------------------| 
| DOC001 | Invalid docstring section                        | Detects unknown Sphinx fields.                                                  | Yes                |
| DOC002 | Malformed section                                | Ensures valid field list syntax.                                                | Yes                |
| DOC003 | Missing blank line after docstring               | Improves readability.                                                           | Yes                |
| DOC004 | Missing blank line between summary and sections  | Enforces structure consistency.                                                 | Yes                |
| DOC005 | Too many consecutive blank lines                 | Prevents unnecessary whitespace.                                                | Yes                |
| DOC006 | Trailing empty lines                             | Keeps docstrings compact.                                                       | Yes                |
| DOC007 | Misplaced section                                | Enforces section order and grouping.                                            | Yes                |
| DOC008 | One-line docstring should end with a period      | Complies with [PEP 257](https://peps.python.org/pep-0257/#one-line-docstrings). | Yes                |
| DOC009 | Docstring must not use more than 3 double quotes | Promotes consistent quoting.                                                    | Yes                |
| DOC010 | Section definition contains invalid whitespace   | Ensures proper formatting.                                                      | Yes                |
| DOC011 | Trailing non-empty lines after last section      | Maintains clean endings.                                                        | Yes                |
| DOC012 | Leading whitespaces in first non-blank line      | Ensures no leading spaces before docstring content.                             | Yes                |

---

> [!NOTE]
>
>  **DOC008**: This rule differs from Ruff’s similar rule [
> `missing-trailing-period`](https://docs.astral.sh/ruff/rules/missing-trailing-period),
> which enforces a trailing period on the first line of both one-line and multi-line docstrings. By contrast, the rule
> **DOC008** only enforces a trailing period on *one-line* docstrings, following the recommendation
> in [PEP 257](https://peps.python.org/pep-0257/#one-line-docstrings).

> [!NOTE]
>
> **DOC009**: Unlike Ruff [
> `triple-single-quotes`](https://docs.astral.sh/ruff/rules/triple-single-quotes/#triple-single-quotes-d300),
> this rule only checks that multi-line docstrings do not start or end with more than three double quotes.

---

### DOC1xx — Parameters

| Code   | Description                               | Purpose                                   | Enabled by Default |
|--------|-------------------------------------------|-------------------------------------------|--------------------|
| DOC101 | Parameter documented but not in signature | Detects undocumented or extra parameters. | Yes                |
| DOC102 | Invalid parameter type syntax             | Enforces valid Python type hints.         | Yes                |
| DOC103 | Parameter type already in signature       | Avoids redundant type info.               | Yes                |
| DOC104 | Parameter type mismatch with annotation   | Ensures consistency with annotations.     | Yes                |
| DOC105 | Duplicated parameter                      | Prevents repetition.                      | Yes                |
| DOC106 | Parameter order mismatch with signature   | Validates parameter order.                | Yes                |
| DOC107 | Missing parameter in docstring            | Ensures all parameters are documented     | No                 |

---

### DOC2xx — Returns

| Code   | Description                                            | Purpose                                 | Enabled by Default |
|--------|--------------------------------------------------------|-----------------------------------------|--------------------|
| DOC201 | Return documented but function has no return statement | Detects unnecessary return sections.    | Yes                |
| DOC202 | Invalid return type syntax                             | Enforces valid type expressions.        | Yes                |
| DOC203 | Return type already in signature                       | Avoids redundancy.                      | Yes                |
| DOC204 | Return type mismatch with annotation                   | Validates against function annotations. | Yes                |
| DOC205 | Duplicated return section                              | Prevents duplication.                   | Yes                |

---

### DOC3xx — Raises

| Code   | Description                   | Purpose                                | Enabled by Default |
|--------|-------------------------------|----------------------------------------|--------------------|
| DOC302 | Invalid exception type syntax | Ensures valid Python exception syntax. | Yes                |
| DOC305 | Duplicated exception type     | Prevents redundant entries.            | Yes                |

---

### DOC4xx — Variables

| Code   | Description                               | Purpose                           | Enabled by Default |
|--------|-------------------------------------------|-----------------------------------|--------------------|
| DOC402 | Invalid variable type syntax              | Enforces valid Python type hints. | Yes                |
| DOC403 | Variable name contains invalid whitespace | Ensures valid identifiers.        | Yes                |
| DOC405 | Duplicated variable                       | Prevents repetition.              | Yes                |

---

## How It Works

The tool statically analyzes Python source code using the built-in AST module:

1. Parses `FunctionDef`, `AsyncFunctionDef`, `ClassDef`, and `Module` nodes.
2. Extracts Sphinx-style docstring fields.
3. Validates structure, syntax, and consistency with annotations.

The tool prints findings to stdout and never modifies source files.

**CI Integration:**  
Treat any output as a failure signal in your build pipeline.

---

## 🛠️ Development

To contribute to the project, you can run the following commands for testing and documentation:

First, ensure you have the latest version of `pip`:

```bash
python -m pip install --upgrade pip
```

### Running Tests

```bash
pip install --group=test --upgrade # Install test dependencies, skip if already installed
python -m pytest tests/ # Run all tests
python -m pytest tests/ --cov # Run tests with coverage
```

### Running Linter

```bash
pip install --group=lint --upgrade  # Install lint dependencies, skip if already installed
ruff check . # Run linter
```

## 🗒️ License

This project is licensed under the [MIT license](LICENSE)._
