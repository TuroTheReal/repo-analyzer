"""actionlint runner for GitHub Actions workflow correctness (domain: PIPELINE).

actionlint catches workflow mistakes: bad syntax, invalid ``${{ }}`` expressions,
shellcheck issues in ``run:`` blocks, deprecated runners. These are correctness
lints (not graded by severity by the tool), so they map to Low. actionlint exits
1 when it finds issues, which is not a tool failure (hence ``ok_codes=(0, 1)``).
"""

from __future__ import annotations

import json
from pathlib import Path

from ..core.finding import Domain, Finding, Severity
from .base import Runner, RunnerError, RunnerResult, run_command, workflow_files


_TIMEOUT_SECONDS = 60


class ActionlintRunner(Runner):
    """Wrap ``actionlint`` and emit pipeline-correctness findings."""

    name = "actionlint"
    binary = "actionlint"

    def run(self, root: Path) -> RunnerResult:
        if not workflow_files(root):
            return RunnerResult([], frozenset())
        stdout = run_command(
            ["actionlint", "-format", "{{json .}}"],
            cwd=root,
            timeout=_TIMEOUT_SECONDS,
            ok_codes=(0, 1),  # 1 = lint issues found (not a tool failure)
        )
        try:
            data = json.loads(stdout) if stdout.strip() else []
        except json.JSONDecodeError as exc:
            raise RunnerError(f"actionlint returned invalid JSON: {exc}") from exc
        return RunnerResult(self._parse(data), frozenset({Domain.PIPELINE}))

    def _parse(self, data: list) -> list[Finding]:
        findings: list[Finding] = []
        for error in data or []:
            findings.append(
                Finding(
                    rule_id=error.get("kind") or "actionlint",
                    title=error.get("message") or "Workflow lint issue",
                    severity=Severity.LOW,  # correctness lint, no severity gradation
                    domain=Domain.PIPELINE,
                    tool=self.name,
                    message=error.get("message") or "",
                    file=error.get("filepath") or None,
                    line=error.get("line") or None,
                )
            )
        return findings
