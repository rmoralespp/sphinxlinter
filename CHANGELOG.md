## Releases

v0.1.1 (2025-11-11)

- **Fixed:** Option --version when used with sphinx-linter as installed package.

### v0.1.0 (2025-11-11)

- **Added:** Rule `DOC012` to check for leading in first non-blank line of docstring.
- **Added:** Rule `DOC106` to check parameter order mismatch with function signature.
- **Added:** Rule `DOC107` to check missing parameters in docstring. (by default disabled)
- **Added:** Add CLI parameter `--version`
- **Added:** Allow read custom configuration from `configuration from `pyproject.toml` files`.

### v0.0.17 (2025-11-07)

- **Added:** Rule `DOC012` to check for leading in first non-blank line of docstring.
- **Changed:** The `DOC010` rule now detects (trailing whitespace and missing leading whitespace).
- **Fixed:** internal code warnings

### v0.0.16 (2025-11-04)

- **Changed:** `CI` workflow to use `sphinxlinter.py` for repository python files linting.
- **Changed:** Added default ignored directories to `--ignore` option. (`env`, `venv`)
- **Changed:** Internal refactoring to improve `DOC003` management.
- **Fixed:** Rule `DOC205` did not alert a warning when there was a duplicate section with different names (`:returns:`
  and `:return:`).

### v0.0.15 (2025-11-03)

- **Fixed:** Rule `DOC003` did not alert a warning when there was a comment after the docstring.

### v0.0.14 (2025-10-30)

- **Added:** Badge for GitHub tag in `README.md` to show latest release version.
- **Changed:** Expanded default ignored directories in `--ignore` option.
- **Changed:** Coverage config (Now it measures branch coverage (conditions) and shows the lines that are not covered)

### v0.0.13 (2025-10-29)

- **Added:** `DOC011` Trailing non-empty lines after last section

### v0.0.12 (2025-10-24)

- **Added:** `DOC010` Section definition contains invalid whitespace
- **Added:** Unit tests for `DOC010` rule.
- **Changed:** Updated README.md to include new rule and examples.

### v0.0.11 (2025-10-20)

- **Changed:** `Readme.md` improvements.
- **Changed:** Descriptions of several rules for clarity.

### v0.0.10 (2025-10-16)

- **Added:** Unit tests for `DOC402` rule.
- **Changed:** Documentation in README.md to include new rules and examples.
- **Changed:** Internal refactoring.
- **Fixed:** Ruff warnings

### v0.0.9 (2025-10-15)

- **Added:** Support por Python 3.14.
- **Added:** Support for checking Variables (`:var`, `:ivar`, `:cvar`, `:vartype`) in docstring sections
- **Added:** project.urls` section to `pyproject.toml`
- **Added:** Support for Module and Class docstring checks.
- **Fixed:** `DOC006` false positive.

### v0.0.8 (2025-09-30)

- **Added:** More unit tests.
- **Added:** `spxl` short command to run the linter from CLI.
- **Added:** Print success message if no issues found.
- **Changed:** `DOC009` message to avoid confusion with **ruff's D300** rule
- **Changed:** `pyproject.toml` to use more ruff rules
- **Fixed:** Fix format warnings.
- **Fixed:** Ignore `DOC008` when docstring is empty.

### v0.0.7 (2025-09-29)

- **Added:** Disable SyntaxWarnings to reduce output noise from python parser.
- **Added:** `DOC008` One-line docstring should end with a period.
- **Added:** `DOC009` Docstring should use """triple double quotes"""

### v0.0.6 (2025-09-25)

- **Added:** `DOC007` to check for misplaced sections in docstrings.
- **Added:** Option `--quiet` to suppress output, except statistics if `--statistics` is set.

### v0.0.5 (2025-09-24)

- **Improved:** `DOC002` to strengthen detection of malformed section(return, rtype) docstring.
- **Fixed:** Sort warning by line number.

### v0.0.4 (2025-09-24)

- **Added:** Sort warning by line number.
- **Added:** Option `--statistics`: to show counts for every rule with at least one violation.
- **Fixed:** Bug in walking directories when using `--ignore` option.

### v0.0.3 (2025-09-18)

- **Added:** Options `--enable` and `--disable` to control specific checks.
- **Changed:** Update README.md to include installation instructions.

### v0.0.2 (2025-09-17)

- **Fixed:** Installation instructions in README.md.

### v0.0.1 (2025-09-17)

- **Added:** Initial release of the project with basic functionality.
