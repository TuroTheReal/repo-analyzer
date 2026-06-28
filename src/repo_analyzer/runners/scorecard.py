"""OpenSSF Scorecard runner: repo supply-chain / governance posture (domain: SUPPLY_CHAIN).

Scorecard inspects the **remote GitHub repo via the API** (branch protection,
signed releases, pinned dependencies, token permissions, dangerous workflows...),
not local files. So it only runs when the scan target is the *root* of a GitHub
repository and an auth token is available; otherwise the supply-chain domain is
left unassessed (e.g. scanning a subdirectory or a non-GitHub folder).

Findings are **advisory**: severity is capped at MEDIUM (posture, not an
exploitable vulnerability) so the default critical/high gate never fails on
governance gaps, and the scorer keeps this domain out of the headline grade.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

from ..core.finding import Domain, Finding, Severity
from .base import Runner, RunnerError, RunnerResult, run_command


# Scorecard hits the GitHub API for ~18 checks; allow a generous timeout.
_TIMEOUT_SECONDS = 300
_GIT_TIMEOUT_SECONDS = 10

# Parses owner/repo out of an origin remote URL (https or ssh, optional .git).
_GITHUB_REMOTE = re.compile(r"github\.com[:/]+([^/]+/[^/]+?)(?:\.git)?/?$")


class ScorecardRunner(Runner):
    """Wrap ``scorecard`` and emit advisory supply-chain posture findings."""

    name = "scorecard"
    binary = "scorecard"

    def run(self, root: Path) -> RunnerResult:
        repo = self._github_repo(root)
        token = os.environ.get("GITHUB_AUTH_TOKEN") or os.environ.get("GITHUB_TOKEN")
        if not repo or not token:
            # Not a GitHub repo root, or no token: leave the domain unassessed.
            return RunnerResult([], frozenset())

        stdout = run_command(
            ["scorecard", f"--repo={repo}", "--format=json"],
            cwd=root,
            timeout=_TIMEOUT_SECONDS,
        )
        try:
            data = json.loads(stdout) if stdout.strip() else {}
        except json.JSONDecodeError as exc:
            raise RunnerError(f"scorecard returned invalid JSON: {exc}") from exc
        return RunnerResult(self._parse(data), frozenset({Domain.SUPPLY_CHAIN}), raw=stdout)

    def _github_repo(self, root: Path) -> str | None:
        """The ``github.com/owner/repo`` to score, or None when not applicable.

        Only the repository *root* is scored (a subdirectory like a test fixture
        belongs to the parent repo, not itself), so a fixture scan never reports
        the parent repo's posture.
        """
        try:
            toplevel = run_command(
                ["git", "rev-parse", "--show-toplevel"], cwd=root, timeout=_GIT_TIMEOUT_SECONDS
            ).strip()
        except RunnerError:
            return None  # not a git repo
        if not toplevel or Path(toplevel).resolve() != root.resolve():
            return None  # scanning a subdirectory, not the repo root

        env_repo = os.environ.get("GITHUB_REPOSITORY")  # set by GitHub Actions: owner/repo
        if env_repo:
            return f"github.com/{env_repo}"
        try:
            url = run_command(
                ["git", "remote", "get-url", "origin"], cwd=root, timeout=_GIT_TIMEOUT_SECONDS
            ).strip()
        except RunnerError:
            return None
        match = _GITHUB_REMOTE.search(url)
        return f"github.com/{match.group(1)}" if match else None

    def _parse(self, data: dict) -> list[Finding]:
        findings: list[Finding] = []
        for check in data.get("checks") or []:
            severity = self._severity(check.get("score"))
            if severity is None:
                continue  # perfect (10) or inconclusive (-1): not a finding
            doc = check.get("documentation") or {}
            name = check.get("name") or "scorecard"
            findings.append(
                Finding(
                    rule_id=name,
                    title=f"{name}: {doc.get('short') or 'supply-chain posture'}",
                    severity=severity,
                    domain=Domain.SUPPLY_CHAIN,
                    tool=self.name,
                    message=check.get("reason") or "",
                    references=(doc["url"],) if doc.get("url") else (),
                )
            )
        return findings

    @staticmethod
    def _severity(score: object) -> Severity | None:
        """Map a Scorecard check score (0-10, or -1 inconclusive) to a capped severity.

        Advisory: never exceeds MEDIUM, so the default critical/high gate is not
        failed by governance posture. A perfect (10) or inconclusive (-1) check
        yields no finding.
        """
        if not isinstance(score, (int, float)) or score < 0 or score >= 10:
            return None
        return Severity.MEDIUM if score < 5 else Severity.LOW
