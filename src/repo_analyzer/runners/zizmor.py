"""zizmor runner for GitHub Actions workflow security (domain: PIPELINE).

zizmor audits workflows for supply-chain and injection risks (unpinned actions,
script injection, excessive permissions, credential persistence...). Run with
``--no-exit-codes`` so a found issue does not make zizmor exit non-zero (our gate
owns the verdict) and ``--offline`` so no GitHub token/network is required.
"""

from __future__ import annotations

import json
from pathlib import Path

from ..core.finding import Domain, Finding, Severity
from .base import Runner, RunnerError, RunnerResult, relative_to_root, run_command, workflow_files


_TIMEOUT_SECONDS = 180

# zizmor emits Informational/Low/Medium/High/Unknown; map onto our severities.
_SEVERITY: dict[str, Severity] = {
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "informational": Severity.INFO,
    "unknown": Severity.INFO,
}


class ZizmorRunner(Runner):
    """Wrap ``zizmor`` and emit pipeline-security findings."""

    name = "zizmor"
    binary = "zizmor"

    def run(self, root: Path) -> RunnerResult:
        workflows = workflow_files(root)
        if not workflows:
            return RunnerResult([], frozenset())
        stdout = run_command(
            ["zizmor", "--offline", "--no-exit-codes", "--format", "json", str(root / ".github" / "workflows")],
            cwd=root,
            timeout=_TIMEOUT_SECONDS,
        )
        try:
            data = json.loads(stdout) if stdout.strip() else []
        except json.JSONDecodeError as exc:
            raise RunnerError(f"zizmor returned invalid JSON: {exc}") from exc
        return RunnerResult(self._parse(data, root), frozenset({Domain.PIPELINE}), raw=stdout)

    def _parse(self, data: list, root: Path | None = None) -> list[Finding]:
        findings: list[Finding] = []
        for item in data or []:
            determinations = item.get("determinations") or {}
            severity = _SEVERITY.get((determinations.get("severity") or "").lower(), Severity.MEDIUM)
            locations = item.get("locations") or []
            location = locations[0] if locations else {}
            given_path = (
                (((location.get("symbolic") or {}).get("key") or {}).get("Local") or {}).get("given_path")
            )
            point = ((location.get("concrete") or {}).get("location") or {}).get("start_point") or {}
            row = point.get("row")
            url = item.get("url")
            findings.append(
                Finding(
                    rule_id=item.get("ident") or "zizmor",
                    title=item.get("desc") or "Workflow security issue",
                    severity=severity,
                    domain=Domain.PIPELINE,
                    tool=self.name,
                    message=item.get("desc") or "",
                    file=relative_to_root(given_path, root),
                    line=(row + 1) if isinstance(row, int) else None,  # zizmor rows are 0-based
                    references=(url,) if url else (),
                )
            )
        return findings
