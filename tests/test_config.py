"""Tests for config loading: defaults, parsing, and strict error handling."""

import pytest

from repo_analyzer.config import (
    DEFAULT_FAIL_ON,
    DEFAULT_FORMATS,
    Config,
    ConfigError,
)
from repo_analyzer.core.finding import Severity


def _write(tmp_path, text, name=".repo-analyzer.yml"):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def test_missing_file_returns_defaults(tmp_path):
    config = Config.load(tmp_path)
    assert config.fail_on == DEFAULT_FAIL_ON
    assert config.formats == DEFAULT_FORMATS


def test_fail_on_and_formats_parsed(tmp_path):
    _write(tmp_path, "gate:\n  fail_on: [critical, low]\noutput:\n  formats: [sarif, json]\n")
    config = Config.load(tmp_path)
    assert config.fail_on == frozenset({Severity.CRITICAL, Severity.LOW})
    assert config.formats == ("sarif", "json")


def test_fail_on_aliases_resolved(tmp_path):
    _write(tmp_path, "gate:\n  fail_on: [moderate, warning]\n")
    assert Config.load(tmp_path).fail_on == frozenset({Severity.MEDIUM})


def test_unknown_severity_is_rejected_not_coerced(tmp_path):
    _write(tmp_path, "gate:\n  fail_on: [critical, banana]\n")
    with pytest.raises(ConfigError):
        Config.load(tmp_path)


def test_empty_gate_falls_back_to_defaults(tmp_path):
    _write(tmp_path, "output:\n  dir: out\n")
    assert Config.load(tmp_path).fail_on == DEFAULT_FAIL_ON


def test_unknown_formats_filtered_to_defaults(tmp_path):
    _write(tmp_path, "output:\n  formats: [xml, pdf]\n")
    assert Config.load(tmp_path).formats == DEFAULT_FORMATS


def test_non_mapping_yaml_raises(tmp_path):
    _write(tmp_path, "just a scalar string")
    with pytest.raises(ConfigError):
        Config.load(tmp_path)


def test_malformed_yaml_raises(tmp_path):
    _write(tmp_path, "gate: [unclosed")
    with pytest.raises(ConfigError):
        Config.load(tmp_path)


def test_from_file_required_missing_raises(tmp_path):
    with pytest.raises(ConfigError):
        Config.from_file(tmp_path / "does-not-exist.yml", required=True)


def test_from_file_loads_custom_named_file(tmp_path):
    path = _write(tmp_path, "gate:\n  fail_on: [low]\n", name="custom.yml")
    assert Config.from_file(path).fail_on == frozenset({Severity.LOW})


def test_skip_dirs_extend_defaults(tmp_path):
    from repo_analyzer.config import DEFAULT_SKIP_DIRS

    _write(tmp_path, "scan:\n  skip_dirs: [tests/fixtures]\n")
    config = Config.load(tmp_path)
    assert "tests/fixtures" in config.skip_dirs
    assert ".git" in config.skip_dirs  # defaults preserved
