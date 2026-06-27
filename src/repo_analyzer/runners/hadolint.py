"""hadolint runner for Dockerfile linting (domain: CONTAINER).

hadolint scans one Dockerfile at a time, so the runner discovers Dockerfiles
under the root and lints each. ``--no-fail`` keeps the exit code 0 regardless of
findings, so the strict run_command check still catches real failures.
"""

from __future__ import annotations

import json
from pathlib import Path

from ..core.finding import Domain, Finding, Severity
from .base import Runner, RunnerError, RunnerResult, run_command


_TIMEOUT_SECONDS = 60

_LEVEL: dict[str, Severity] = {
    "error": Severity.HIGH,
    "warning": Severity.MEDIUM,
    "info": Severity.LOW,
    "style": Severity.INFO,
}

_GLOBS = ("Dockerfile", "Dockerfile.*", "*.Dockerfile", "Containerfile")


class HadolintRunner(Runner):
    """Wrap ``hadolint`` over every Dockerfile under the root."""

    name = "hadolint"
    binary = "hadolint"
    domains = (Domain.CONTAINER,)

    def run(self, root: Path) -> RunnerResult:
        dockerfiles = self._discover(root)
        findings: list[Finding] = []
        for dockerfile in dockerfiles:
            findings.extend(self._lint(dockerfile, root))
        # Assessable only when at least one Dockerfile exists to lint.
        assessed = frozenset({Domain.CONTAINER}) if dockerfiles else frozenset()
        return RunnerResult(findings, assessed)

    def _discover(self, root: Path) -> list[Path]:
        seen: set[Path] = set()
        for glob in _GLOBS:
            for path in root.rglob(glob):
                if path.is_file():
                    seen.add(path)
        return sorted(seen)

    def _lint(self, dockerfile: Path, root: Path) -> list[Finding]:
        stdout = run_command(
            ["hadolint", "--no-fail", "-f", "json", str(dockerfile)],
            cwd=root,
            timeout=_TIMEOUT_SECONDS,
        )
        try:
            data = json.loads(stdout) if stdout.strip() else []
        except json.JSONDecodeError as exc:
            raise RunnerError(f"hadolint returned invalid JSON: {exc}") from exc
        return self._parse(data, _relative(dockerfile, root))

    def _parse(self, data: list, rel: str) -> list[Finding]:
        findings: list[Finding] = []
        for issue in data or []:
            code = issue.get("code") or "hadolint"
            references = (f"https://github.com/hadolint/hadolint/wiki/{code}",) if code.startswith("DL") else ()
            findings.append(
                Finding(
                    rule_id=code,
                    title=issue.get("message") or "Dockerfile issue",
                    severity=_LEVEL.get((issue.get("level") or "").lower(), Severity.INFO),
                    domain=Domain.CONTAINER,
                    tool=self.name,
                    message=issue.get("message") or "",
                    file=rel,
                    line=issue.get("line") or None,
                    references=references,
                )
            )
        return findings


def _relative(path: Path, root: Path) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve()))
    except ValueError:
        return path.name
