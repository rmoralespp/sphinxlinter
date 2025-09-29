## Releases

- **Added:** Disable SyntaxWarnings to reduce output noise from python parser.
- **Added:** `DOC008` One-line docstring should end with a period.
- **Added**: `DOC206` Generator is not compatible with documented return type.
- **Fixed:** `DOC008` Ignore multi-line docstrings with ignored sections or invalid sections.

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
