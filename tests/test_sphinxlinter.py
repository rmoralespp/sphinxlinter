# -*- coding: utf-8 -*-

import ast
import keyword
import pathlib
import tempfile
import unittest.mock

import pytest

import sphinxlinter

ok_type_hints_kw = keyword.softkwlist + ["False", "None", "True"]
ko_type_hints_kw = [kw for kw in (keyword.kwlist + keyword.softkwlist) if kw not in ok_type_hints_kw]


@pytest.fixture
def tmp_dirpath():
    with tempfile.TemporaryDirectory() as tmp:
        yield pathlib.Path(tmp)


def dump_config(tmp_dirpath, lines, /):
    config_file = tmp_dirpath / "pyproject.toml"
    config_file.write_text("\n".join(lines))
    return str(config_file)


class TestViolations:

    @pytest.mark.parametrize("hint, expected", [
        ("", False),
        ("int", True),
        ("str", True),
        ("list[int]", True),
        ("dict[str, Any]", True),
        # valid syntax, but not a type hint
        # --------------------------------------------------------------------
        ("2 + 2", True),
        ("NotFound", True),
        ("...", True),
        ("foo()", True),
        # invalid syntax
        # --------------------------------------------------------------------
        ("list[]", False),
        ("list[int", False),
        ("dict[int; Any]", False),
        # --------------------------------------------------------------------
        # keywords in type hints
        # --------------------------------------------------------------------
        *tuple(zip(ok_type_hints_kw, (True,) * len(ok_type_hints_kw))),
        *tuple(zip(ko_type_hints_kw, (False,) * len(ko_type_hints_kw))),
    ])
    def test_is_valid_type_hint(self, hint, expected):
        result = sphinxlinter.Violations.is_valid_type_hint(hint)
        assert result == expected

    def test_validate_summary(self):
        # Test condition when there is no summary at all

        content = '''
def dummy():
    """
    :return: foo
    """

    pass
'''

        parsed = sphinxlinter.parse_docs(ast.parse(content).body[0], "dummy.py")
        result = tuple(sphinxlinter.Violations.validate_summary(parsed))
        assert not result

    @pytest.mark.parametrize("value", (None, ""))
    def test_validate_blank_lines(self, value):
        # Test condition when there is no docstring (or empty)
        parsed = sphinxlinter.ParsedDocs(
            kind="function",
            summary=None,
            params=list(),
            raises=list(),
            returns=list(),
            variables=list(),
            invalid=list(),
            ignored=list(),
            bad_whitespaces_def=list(),
            non_blank_end_lines=False,
            rawdocs=value,
            docs=None,
            docs_ini_lineno=None,
            docs_end_lineno=None,
            missing_blank_line_after=False,
        )
        result = tuple(sphinxlinter.Violations.validate_blank_lines(parsed))
        assert not result

    @pytest.mark.parametrize(
        "docstring, expected",
        (
            (None, None),
            ("", None),
            (" a\nb \n\n ", " a\nb \n\n "),
            (" a \n:b: \n\n", " a \n"),
        ),
    )
    def test_get_summary(self, docstring, expected):
        result = sphinxlinter.get_summary(docstring)
        assert result == expected

    def test_empty_docstring(self):
        content = '''
def dummy():
    pass
'''
        # Test empty docstring does not return sections
        expected = sphinxlinter.ParsedDocs(
            kind="function",
            summary=None,
            params=list(),
            raises=list(),
            returns=list(),
            variables=list(),
            invalid=list(),
            ignored=list(),
            bad_whitespaces_def=list(),
            non_blank_end_lines=False,
            rawdocs=None,
            docs=None,
            docs_ini_lineno=None,
            docs_end_lineno=None,
            missing_blank_line_after=False,
        )
        result = sphinxlinter.parse_docs(ast.parse(content).body[0], "dummy.py")
        assert result == expected

    @pytest.mark.parametrize("quiet", (False, True))
    def test_walk_module_syntax_error(self, quiet):
        data = object()
        filename = object()
        expected = tuple()
        with unittest.mock.patch("sphinxlinter.ast.parse", side_effect=SyntaxError) as parser:
            result = tuple(sphinxlinter.walk_module(quiet, data, filename))

        assert result == expected
        parser.assert_called_once_with(data, filename=filename)

    @pytest.mark.parametrize("quiet", (False, True))
    def test_walk_module(self, quiet):
        data = object()
        filename = object()
        guard = object()
        module = ast.Module()
        functiondef = ast.FunctionDef("foo", tuple())
        asyncfunctiondef = ast.AsyncFunctionDef("bar", tuple())
        classdef = ast.ClassDef("zas", tuple())
        expected = (
            module,
            functiondef,
            asyncfunctiondef,
            classdef,
        )
        walk = (
            module,
            ast.Return(),
            functiondef,
            asyncfunctiondef,
            classdef,
        )
        with (
            unittest.mock.patch("sphinxlinter.ast.parse", return_value=guard) as parser,
            unittest.mock.patch("sphinxlinter.ast.walk", return_value=walk) as walker,
        ):
            result = tuple(sphinxlinter.walk_module(quiet, data, filename))

        assert result == expected
        parser.assert_called_once_with(data, filename=filename)
        walker.assert_called_once_with(guard)

    def test_check_node_no_warnings(self):
        node = object()
        violations = object()
        lines = tuple()
        with unittest.mock.patch("sphinxlinter.checker", return_value=lines) as checker:
            result = tuple(sphinxlinter.check_node(node, violations, "dummy.py"))

        checker.assert_called_once_with(node, violations, "dummy.py")
        assert not result

    def test_check_node_warnings(self):
        node = object()
        violations = object()
        lines = (
            # unsorted line numbers
            (3, "CODE00X", "bar {}-{}", (True, 5)),
            (1, "CODE001", "message", tuple()),
        )
        expected = (
            (3, "CODE00X", "bar True-5"),
            (1, "CODE001", "message"),
        )
        with (
            unittest.mock.patch("sphinxlinter.checker", return_value=lines) as checker,
        ):
            result = tuple(sphinxlinter.check_node(node, violations, "dummy.py"))

        checker.assert_called_once_with(node, violations, "dummy.py")
        assert result == expected

    @pytest.mark.parametrize("value", ("ALL", ("ALL", "FOO")))
    def test_enable_all(self, value):
        expected = frozenset(name for name in dir(sphinxlinter.Violations) if name.startswith("DOC"))
        obj = sphinxlinter.Violations(enable=value)
        result = obj.valid
        assert result == expected

    @pytest.mark.parametrize(
        "enable,disable,expected",
        (
            ((1,), (1,), frozenset()),
            ((1,), (2,), frozenset((1,))),
            ((1, 2, 3), (2,), frozenset((1, 3))),
        ),
    )
    def test_disable(self, enable, disable, expected):
        obj = sphinxlinter.Violations(enable=enable, disable=disable)
        result = obj.valid
        assert result == expected

    def test_discover(self):
        # Test code not in valid rules.
        parsed_docs = object()
        parsed_func = object()
        obj = sphinxlinter.Violations(enable=(1, 3))
        values = (
            ((True, 1, "msg1"), "ctx1"),
            ((False, 2, "msg2"), "ctx2"),
            ((False, 3, "msg3"), "ctx3"),
        )
        expected = (
            ((1, "msg1"), "ctx1"),
            ((3, "msg3"), "ctx3"),
        )
        with unittest.mock.patch.object(obj, "discover_all", return_value=values) as discovered:
            result = tuple(obj.discover(parsed_docs, parsed_func))

        discovered.assert_called_once_with(parsed_docs, parsed_func)
        assert result == expected


@pytest.mark.parametrize(
    "mock_toml_content, expected_version",
    [
        ({"project": {"version": "1.0.0"}}, "sphinx-linter 1.0.0"),
        ({"project": {"version": "2.5.3"}}, "sphinx-linter 2.5.3"),
    ],
)
def test_dump_version_ok(mock_toml_content, expected_version):
    toml_str = "\n".join((
        '[project]',
        'version = \"{}\"'.format(mock_toml_content['project']['version']),
    ))
    with (
        unittest.mock.patch("pathlib.Path.open", unittest.mock.mock_open(read_data=toml_str.encode())),
        unittest.mock.patch("builtins.print") as mock_print,
    ):
        sphinxlinter.dump_version()
        mock_print.assert_called_once_with(expected_version)


def test_dump_version_ko_missing_version():
    with (
        unittest.mock.patch("pathlib.Path.open", unittest.mock.mock_open(read_data=b"")),
        pytest.raises(KeyError),
    ):
        sphinxlinter.dump_version()


def test_dump_version_ko_file_not_found():
    with (
        unittest.mock.patch("pathlib.Path.open", side_effect=FileNotFoundError),
        pytest.raises(FileNotFoundError),
    ):
        sphinxlinter.dump_version()


class TestGetConfigStartDir:

    def test_single_file(self, tmp_dirpath):
        file = tmp_dirpath / "test.py"
        file.touch()
        result = sphinxlinter.get_config_start_dir([str(file)])
        assert result == str(tmp_dirpath)

    def test_single_directory(self, tmp_dirpath):
        result = sphinxlinter.get_config_start_dir([str(tmp_dirpath)])
        assert result == str(tmp_dirpath)

    def test_multiple_files_same_directory(self, tmp_dirpath):
        file1 = tmp_dirpath / "test1.py"
        file2 = tmp_dirpath / "test2.py"
        file1.touch()
        file2.touch()
        result = sphinxlinter.get_config_start_dir([str(file1), str(file2)])
        assert result == str(tmp_dirpath)

    def test_multiple_files_nested_directories(self, tmp_dirpath):
        subdir = tmp_dirpath / "subdir"
        subdir.mkdir()
        file1 = tmp_dirpath / "test1.py"
        file2 = subdir / "test2.py"
        file1.touch()
        file2.touch()
        result = sphinxlinter.get_config_start_dir([str(file1), str(file2)])
        assert result == str(tmp_dirpath)

    def test_multiple_directories(self, tmp_dirpath):
        dir1 = tmp_dirpath / "dir1"
        dir2 = tmp_dirpath / "dir2"
        dir1.mkdir()
        dir2.mkdir()
        result = sphinxlinter.get_config_start_dir([str(dir1), str(dir2)])
        assert result == str(tmp_dirpath)

    def test_mixed_files_and_directories(self, tmp_dirpath):
        subdir = tmp_dirpath / "subdir"
        subdir.mkdir()
        file = tmp_dirpath / "test.py"
        file.touch()
        result = sphinxlinter.get_config_start_dir([str(file), str(subdir)])
        assert result == str(tmp_dirpath)

    def test_deeply_nested_paths(self, tmp_dirpath):
        deep1 = tmp_dirpath / "a" / "b" / "c"
        deep2 = tmp_dirpath / "a" / "b" / "d"
        deep1.mkdir(parents=True)
        deep2.mkdir(parents=True)
        file1 = deep1 / "test1.py"
        file2 = deep2 / "test2.py"
        file1.touch()
        file2.touch()
        result = sphinxlinter.get_config_start_dir([str(file1), str(file2)])
        assert result == str(tmp_dirpath / "a" / "b")


class TestLoadConfig:

    def test_explicit_config_file_with_sphinx_linter_section(self, tmp_dirpath):
        config_lines = (
            '[tool.sphinx-linter]',
            'enable = ["DOC001", "DOC002"]',
            'disable = ["DOC003"]',
        )
        config_file = dump_config(tmp_dirpath, config_lines)
        result = sphinxlinter.load_config(str(config_file), [])

        expected = {"enable": ["DOC001", "DOC002"], "disable": ["DOC003"]}
        assert result == expected

    def test_explicit_config_file_without_sphinx_linter_section(self, tmp_dirpath):
        config_lines = (
            '[tool.other]',
            'enable = ["DOC001", "DOC002"]',
            'disable = ["DOC003"]',
        )
        config_file = dump_config(tmp_dirpath, config_lines)
        result = sphinxlinter.load_config(str(config_file), [])
        assert result == {}

    def test_explicit_config_file_malformed_toml(self, tmp_dirpath):
        config_file = tmp_dirpath / "pyproject.toml"
        config_file.write_text("this is not valid TOML {][")  # Malformed TOML file
        result = sphinxlinter.load_config(str(config_file), [])
        assert result == {}

    def test_explicit_config_file_not_found(self, tmp_dirpath):
        config_file = tmp_dirpath / "pyproject.toml"  # Config file does not exist
        with pytest.raises(FileNotFoundError):
            sphinxlinter.load_config(str(config_file), [])

    def test_implicit_config_in_same_directory(self, tmp_dirpath):
        test_file = tmp_dirpath / "test.py"  # pyproject.toml in the same directory as the file
        test_file.touch()

        config_lines = (
            '[tool.sphinx-linter]',
            'enable = ["ALL"]',
        )
        dump_config(tmp_dirpath, config_lines)

        result = sphinxlinter.load_config(None, [str(test_file)])
        expected = {"enable": ["ALL"]}
        assert result == expected

    def test_implicit_config_in_parent_directory(self, tmp_dirpath):
        # pyproject.toml in parent directory
        subdir = tmp_dirpath / "subdir"
        subdir.mkdir()
        test_file = subdir / "test.py"
        test_file.touch()

        config_lines = (
            '[tool.sphinx-linter]',
            'disable = ["DOC001"]',
        )
        dump_config(tmp_dirpath, config_lines)

        expected = {"disable": ["DOC001"]}
        result = sphinxlinter.load_config(None, [str(test_file)])
        assert result == expected

    def test_implicit_config_multiple_levels_up(self, tmp_dirpath):
        # pyproject.toml several levels up
        deep_dir = tmp_dirpath / "a" / "b" / "c"
        deep_dir.mkdir(parents=True)
        test_file = deep_dir / "test.py"
        test_file.touch()

        config_lines = (
            '[tool.sphinx-linter]',
            'ignore = ["venv", ".git"]',
        )
        dump_config(tmp_dirpath, config_lines)

        result = sphinxlinter.load_config(None, [str(test_file)])

        expected = {"ignore": ["venv", ".git"]}
        assert result == expected

    def test_implicit_config_not_found(self, tmp_dirpath):
        # No pyproject.toml found in any parent directory
        test_file = tmp_dirpath / "test.py"
        test_file.touch()
        result = sphinxlinter.load_config(None, [str(test_file)])
        assert result == {}

    def test_implicit_config_closest_file_wins(self, tmp_dirpath):
        # Multiple pyproject.toml files, closest one should win
        subdir = tmp_dirpath / "subdir"
        subdir.mkdir()
        test_file = subdir / "test.py"
        test_file.touch()

        # Parent config
        parent_config_lines = (
            '[tool.sphinx-linter]',
            'enable = ["DOC001"]',
        )
        dump_config(tmp_dirpath, parent_config_lines)

        # Closer config, wins over parent
        closer_config_lines = (
            '[tool.sphinx-linter]',
            'enable = ["DOC002"]',
        )
        dump_config(subdir, closer_config_lines)

        result = sphinxlinter.load_config(None, [str(test_file)])

        expected = {"enable": ["DOC002"]}
        assert result == expected

    def test_implicit_config_with_multiple_files(self, tmp_dirpath):
        # Multiple check files, use common ancestor
        subdir1 = tmp_dirpath / "dir1"
        subdir2 = tmp_dirpath / "dir2"
        subdir1.mkdir()
        subdir2.mkdir()

        file1 = subdir1 / "test1.py"
        file2 = subdir2 / "test2.py"
        file1.touch()
        file2.touch()

        config_lines = (
            '[tool.sphinx-linter]',
            'enable = ["DOC001", "DOC002"]',
        )
        dump_config(tmp_dirpath, config_lines)

        result = sphinxlinter.load_config(None, [str(file1), str(file2)])

        assert result == {"enable": ["DOC001", "DOC002"]}

    def test_explicit_config_with_full_settings(self, tmp_dirpath):
        # Test with various configuration options
        config_file = tmp_dirpath / "pyproject.toml"
        config_lines = (
            '[tool.sphinx-linter]',
            'enable = ["DOC001", "DOC101", "DOC201"]',
            'disable = ["DOC008"]',
            'ignore = ["venv", ".venv", "__pycache__"]',
        )
        dump_config(tmp_dirpath, config_lines)

        result = sphinxlinter.load_config(str(config_file), [])

        expected = {
            "enable": ["DOC001", "DOC101", "DOC201"],
            "disable": ["DOC008"],
            "ignore": ["venv", ".venv", "__pycache__"],
        }
        assert result == expected

    def test_implicit_config_skips_malformed_files(self, tmp_dirpath):
        # Malformed pyproject.toml should be skipped
        subdir = tmp_dirpath / "subdir"
        subdir.mkdir()
        test_file = subdir / "test.py"
        test_file.touch()

        # Malformed config in subdir (should be skipped)
        bad_config = subdir / "pyproject.toml"
        bad_config.write_text("invalid toml {][")

        # Valid config in parent
        good_config_lines = (
            '[tool.sphinx-linter]',
            'enable = ["DOC001"]',
        )
        dump_config(tmp_dirpath, good_config_lines)

        result = sphinxlinter.load_config(None, [str(test_file)])

        assert result == {"enable": ["DOC001"]}

    def test_implicit_config_with_directory_path(self, tmp_dirpath):
        # Check files contains a directory instead of a file
        subdir = tmp_dirpath / "subdir"
        subdir.mkdir()
        config_lines = (
            '[tool.sphinx-linter]',
            'enable = ["ALL"]',
        )
        dump_config(tmp_dirpath, config_lines)
        result = sphinxlinter.load_config(None, [str(subdir)])
        expected = {"enable": ["ALL"]}
        assert result == expected
