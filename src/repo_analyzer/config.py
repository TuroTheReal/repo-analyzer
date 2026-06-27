"""Configuration loading for the gate.

Defaults are sensible out of the box; a repo can override them with a
``.repo-analyzer.yml`` at its root:

    gate:
      fail_on: [critical, high]   # severities that fail the build
    output:
      formats: [sarif, markdown, html, json]
      dir: repo-analyzer-report

A malformed file (unparseable, not a mapping, or an unknown severity in
``fail_on``) raises :class:`ConfigError` so the CLI can surface it as a clean
usage error rather than crash with a traceback.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

from .core.finding import Severity


DEFAULT_FAIL_ON: frozenset[Severity] = frozenset({Severity.CRITICAL, Severity.HIGH})
DEFAULT_FORMATS: tuple[str, ...] = ("sarif", "markdown", "html", "json")
DEFAULT_OUTPUT_DIR: str = "repo-analyzer-report"
DEFAULT_SKIP_DIRS: tuple[str, ...] = (
    ".git", "node_modules", ".venv", "venv", ".terraform",
    "dist", "build", "__pycache__", ".mypy_cache", ".pytest_cache",
)
CONFIG_FILENAME: str = ".repo-analyzer.yml"


class ConfigError(ValueError):
    """Raised on a malformed configuration file."""


@dataclass(frozen=True)
class Config:
    """Resolved gate configuration."""

    fail_on: frozenset[Severity] = DEFAULT_FAIL_ON
    formats: tuple[str, ...] = DEFAULT_FORMATS
    output_dir: str = DEFAULT_OUTPUT_DIR
    skip_dirs: tuple[str, ...] = DEFAULT_SKIP_DIRS

    @classmethod
    def load(cls, root: Path) -> "Config":
        """Load ``<root>/.repo-analyzer.yml`` if present, else return defaults."""
        return cls.from_file(root / CONFIG_FILENAME, required=False)

    @classmethod
    def from_file(cls, path: Path, required: bool = True) -> "Config":
        """Load a specific config file.

        Args:
            path: The config file to read.
            required: When True, a missing file raises :class:`ConfigError`
                (used by ``--config``); when False, it returns defaults (used by
                the conventional auto-discovery).

        Raises:
            ConfigError: File missing (when required), unparseable, not a
                mapping, or containing an unknown severity in ``fail_on``.
        """
        if not path.exists():
            if required:
                raise ConfigError(f"config file not found: {path}")
            return cls()

        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            raise ConfigError(f"invalid YAML in {path}: {exc}") from exc

        if data is None:
            data = {}
        if not isinstance(data, dict):
            raise ConfigError(f"{path}: top level must be a mapping, got {type(data).__name__}")

        gate = data.get("gate") or {}
        output = data.get("output") or {}
        scan = data.get("scan") or {}

        return cls(
            fail_on=_parse_fail_on(gate.get("fail_on"), source=str(path)),
            formats=_parse_formats(output.get("formats")),
            output_dir=str(output.get("dir") or DEFAULT_OUTPUT_DIR),
            skip_dirs=_parse_skip_dirs(scan.get("skip_dirs")),
        )


def _parse_fail_on(value: object, source: str = "config") -> frozenset[Severity]:
    """Parse ``gate.fail_on``; reject unknown severities instead of coercing them."""
    if value is None:
        return DEFAULT_FAIL_ON
    if not isinstance(value, list):
        raise ConfigError(f"{source}: gate.fail_on must be a list")

    parsed: set[Severity] = set()
    for item in value:
        severity = Severity.try_parse(str(item))
        if severity is None:
            raise ConfigError(f"{source}: unknown severity in gate.fail_on: {item!r}")
        parsed.add(severity)
    return frozenset(parsed) or DEFAULT_FAIL_ON


def _parse_formats(value: object) -> tuple[str, ...]:
    """Parse ``output.formats``, keeping only known reporters."""
    if not isinstance(value, list) or not value:
        return DEFAULT_FORMATS
    known = set(DEFAULT_FORMATS)
    formats = tuple(str(item).strip().lower() for item in value if str(item).strip().lower() in known)
    return formats or DEFAULT_FORMATS


def _parse_skip_dirs(value: object) -> tuple[str, ...]:
    """Parse ``scan.skip_dirs``; user entries extend the defaults (deduped)."""
    if not isinstance(value, list):
        return DEFAULT_SKIP_DIRS
    extra = [str(item).strip() for item in value if str(item).strip()]
    return tuple(dict.fromkeys([*DEFAULT_SKIP_DIRS, *extra]))
