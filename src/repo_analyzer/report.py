"""The :class:`Report` bundle handed to every reporter.

It is built once by the CLI from the merged findings and the score, then
rendered into each requested format. Keeping a single immutable bundle means
the reporters can never disagree on the numbers.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .core.finding import Finding
from .core.scorer import ScoreResult


@dataclass(frozen=True)
class Report:
    """Everything the reporters need, computed once."""

    repo_name: str
    target: str
    generated_at: str
    findings: list[Finding]
    score: ScoreResult
    tools: list[str]
    duplicates_removed: int
    #: Tools whose raw native report was written next to this report (raw/<tool>.json).
    raw_tools: list[str] = field(default_factory=list)
