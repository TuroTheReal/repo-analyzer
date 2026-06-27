"""Unified finding model shared by every runner and reporter.

Each scanner produces tool-specific output; runners translate that into a list
of :class:`Finding` objects so the merger, scorer and reporters only ever deal
with one shape.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from functools import total_ordering


_SEVERITY_RANK: dict[str, int] = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}

# Aliases used by scanners that don't speak our five canonical severities.
_SEVERITY_ALIASES: dict[str, str] = {
    "moderate": "medium",
    "warning": "medium",
    "error": "high",
    "note": "low",
    "negligible": "low",
    "unknown": "info",
    "none": "info",
}


@total_ordering
class Severity(Enum):
    """Finding severity, ordered from INFO (lowest) to CRITICAL (highest)."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        """Numeric rank used for comparisons and penalty lookups."""
        return _SEVERITY_RANK[self.value]

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank < other.rank

    @classmethod
    def try_parse(cls, value: str | None) -> "Severity | None":
        """Parse a severity, returning ``None`` for empty or unknown input.

        Use this when an unknown token must NOT be silently coerced, e.g. when
        parsing gate configuration (a typo in ``fail_on`` should be rejected,
        not turned into MEDIUM).
        """
        if not value:
            return None
        normalized = value.strip().lower()
        normalized = _SEVERITY_ALIASES.get(normalized, normalized)
        try:
            return cls(normalized)
        except ValueError:
            return None

    @classmethod
    def from_str(cls, value: str | None, default: "Severity | None" = None) -> "Severity":
        """Parse a severity from arbitrary tool output, falling back to ``default``.

        Tools use inconsistent casing and a few aliases (``moderate``,
        ``warning``, ``error``); normalize them here so runners stay simple.
        ``default`` defaults to :attr:`MEDIUM` when not provided. For scanner
        output a lenient fallback is desirable; for gate config use
        :meth:`try_parse` instead.
        """
        fallback = default if default is not None else cls.MEDIUM
        parsed = cls.try_parse(value)
        return parsed if parsed is not None else fallback


class Domain(Enum):
    """Security domain a finding belongs to. Drives per-domain scoring."""

    IAC = "iac"
    CONTAINER = "container"
    SECRETS = "secrets"
    DEPENDENCIES = "dependencies"
    PIPELINE = "pipeline"
    SUPPLY_CHAIN = "supply_chain"


@dataclass(frozen=True)
class Finding:
    """A single security finding, normalized across tools.

    Attributes:
        rule_id: Stable identifier of the violated rule (e.g. ``CKV_AWS_19``).
        title: Short human-readable summary.
        severity: Normalized severity.
        domain: Security domain (drives scoring weight).
        tool: Name of the scanner that produced the finding.
        message: Longer description of the problem.
        file: Path to the offending file, relative to the scanned root.
        line: 1-based line number, when known.
        resource: Logical resource identifier (e.g. ``aws_s3_bucket.logs``).
        remediation: How to fix it, when the tool provides it.
        references: External links (advisories, docs).
    """

    rule_id: str
    title: str
    severity: Severity
    domain: Domain
    tool: str
    message: str = ""
    file: str | None = None
    line: int | None = None
    resource: str | None = None
    remediation: str | None = None
    references: tuple[str, ...] = field(default_factory=tuple)

    @property
    def dedup_key(self) -> str:
        """Identity used to deduplicate findings reported by several tools.

        Two findings are considered the same when they point at the same rule,
        file, line and resource. The line is intentionally part of the key so a
        rule violated twice in one file counts twice.
        """
        return "|".join(
            (
                self.rule_id.strip().lower(),
                (self.file or "").strip().lower(),
                str(self.line or ""),
                (self.resource or "").strip().lower(),
            )
        )
