# sphinx-linter

A lightweight Python linter for checking Sphinx docstrings and ensuring they follow the recommended field list style:

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

Quick usage, runs on the current working directory by default.

```bash
python sphinxlinter.py
```

Pass one or more files or directories. Directories are searched recursively for `*.py`, ignoring common virtualenv/cache folders.

```bash
python sphinxlinter.py path/to/file.py path/to/package_dir
```

Example output
```text
/path/to/module.py:42: [DOC102] Invalid parameter type syntax ('List[int]')
/path/to/module.py:10: [DOC101] Parameter documented but not in signature ('unused_param')
```

Format: `filename:line: [CODE] message` 

Common violation codes:
- `DOC0xx`:Docstring section issues  
- `DOC1xx`: Parameter issues
- `DOC2xx`: Return issues
- `DOC3xx`: Raises issues

How it works (brief)
- Parses Python AST to find `FunctionDef` and `ClassDef` members.  
- Extracts signatures and docstring sections [Sphinx field lists](https://www.sphinx-doc.org/en/master/usage/domains/python.html#info-field-lists).  
- Validates section presence, syntax and consistency with type annotations.

Notes
- The tool prints findings to stdout and does not modify files.  
- To integrate into CI, run the script and treat any stdout lines as failures in your pipeline logic.

## Style violation codes

**DOC0xx: Docstring section issues**

| Code   | Description                                            |
|--------|--------------------------------------------------------|
| DOC001 | Unknown docstring section                              |
| DOC002 | Malformed section                                      |
| DOC003 | Missing blank line after docstring                     |
| DOC004 | Missing blank line between summary and sections (TODO) |

**DOC1xx: Parameter issues**

| Code   | Description                               |
|--------|-------------------------------------------|
| DOC101 | Parameter documented but not in signature |
| DOC102 | Invalid parameter type syntax             |
| DOC103 | Parameter type already in signature       |
| DOC104 | Parameter type mismatch with hint         |
| DOC105 | Duplicate parameter                       |

**DOC2xx: Return issues**

| Code   | Description                                  |
|--------|----------------------------------------------|
| DOC201 | Return documented but function has no return |
| DOC202 | Invalid return type syntax                   |
| DOC203 | Return type already in signature             |
| DOC204 | Return type mismatch with annotation         |

**DOC3xx: Raises issues**

| Code   | Description                     |
|--------|---------------------------------|
| DOC301 | Invalid exception type syntax   |
