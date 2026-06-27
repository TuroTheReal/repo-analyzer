"""gitleaks runner for hardcoded-secret detection (domain: SECRETS).

Runs with ``--exit-code 0`` so a found secret does not make gitleaks exit
non-zero (our gate owns the pass/fail decision). The secret value itself is
never copied into a finding.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from ..core.finding import Domain, Finding, Severity
from .base import Runner, RunnerError, RunnerResult, relative_to_root, run_command


_TIMEOUT_SECONDS = 180


class GitleaksRunner(Runner):
    """Wrap ``gitleaks dir`` and emit secret findings."""

    name = "gitleaks"
    binary = "gitleaks"

    def run(self, root: Path) -> RunnerResult:
        # gitleaks cannot write its report to a subprocess pipe (/dev/stdout),
        # so we hand it a real temp file and read it back.
        fd, report_path = tempfile.mkstemp(suffix=".json", prefix="gitleaks-")
        os.close(fd)
        try:
            run_command(
                [
                    "gitleaks", "dir", str(root),
                    "--report-format", "json",
                    "--report-path", report_path,
                    "--exit-code", "0",
                    "--no-banner",
                ],
                cwd=root,
                timeout=_TIMEOUT_SECONDS,
            )
            content = Path(report_path).read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            raise RunnerError(f"gitleaks report unreadable: {exc}") from exc
        finally:
            try:
                os.unlink(report_path)
            except OSError:
                pass

        try:
            data = json.loads(content) if content.strip() else []
        except json.JSONDecodeError as exc:
            raise RunnerError(f"gitleaks returned invalid JSON: {exc}") from exc
        # Secret scanning applies to any repo (all files are scanned), so the
        # domain is always assessed: zero secrets is a meaningful clean result.
        return RunnerResult(self._parse(data, root), frozenset({Domain.SECRETS}))

    def _parse(self, data: list, root: Path | None = None) -> list[Finding]:
        findings: list[Finding] = []
        for leak in data or []:
            rule = leak.get("RuleID") or "secret"
            findings.append(
                Finding(
                    rule_id=rule,
                    title=leak.get("Description") or "Hardcoded secret detected",
                    severity=Severity.HIGH,  # exposed credentials fail the default gate
                    domain=Domain.SECRETS,
                    tool=self.name,
                    # Never include the secret value; only where and which rule.
                    message=f"Potential secret matched rule '{rule}'.",
                    file=relative_to_root(leak.get("File"), root),
                    line=leak.get("StartLine") or None,
                    remediation="Rotate the credential and purge it from git history.",
                )
            )
        return findings


