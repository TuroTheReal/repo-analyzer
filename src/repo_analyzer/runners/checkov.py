"""checkov runner for IaC scanning (domain: IAC).

Complements Trivy with a second, independent IaC policy engine. Rule ids differ
between the two engines (``CKV_AWS_*`` vs ``AVD-*``), so they are largely
additive rather than duplicative; the merger still dedups any that coincide.
``--soft-fail`` keeps the exit code 0 regardless of findings.
"""

from __future__ import annotations

import json
from pathlib import Path

from ..core.finding import Finding, Severity
from .base import Runner, RunnerError, RunnerResult, domain_for_iac_type, run_command


_TIMEOUT_SECONDS = 300


class CheckovRunner(Runner):
    """Wrap ``checkov -d <root>`` and emit IaC findings."""

    name = "checkov"
    binary = "checkov"

    def run(self, root: Path) -> RunnerResult:
        stdout = run_command(
            ["checkov", "-d", str(root), "-o", "json", "--compact", "--quiet", "--soft-fail"],
            cwd=root,
            timeout=_TIMEOUT_SECONDS,
        )
        try:
            data = json.loads(stdout) if stdout.strip() else []
        except json.JSONDecodeError as exc:
            raise RunnerError(f"checkov returned invalid JSON: {exc}") from exc

        reports = data if isinstance(data, list) else [data]
        applicable = {
            domain_for_iac_type(r.get("check_type"))
            for r in reports
            if isinstance(r, dict)
            and ((r.get("results") or {}).get("passed_checks") or (r.get("results") or {}).get("failed_checks"))
        }
        return RunnerResult(self._parse(data), frozenset(applicable))

    def _parse(self, data: object) -> list[Finding]:
        # checkov emits a single object for one framework, a list for several.
        reports = data if isinstance(data, list) else [data]
        findings: list[Finding] = []
        for report in reports:
            if not isinstance(report, dict):
                continue
            domain = domain_for_iac_type(report.get("check_type"))
            failed = (report.get("results") or {}).get("failed_checks") or []
            for check in failed:
                line_range = check.get("file_line_range") or []
                guideline = check.get("guideline")
                findings.append(
                    Finding(
                        rule_id=check.get("check_id") or "UNKNOWN",
                        title=check.get("check_name") or "Misconfiguration",
                        # checkov omits severity without a platform key; default applies.
                        severity=Severity.from_str(check.get("severity")),
                        domain=domain,
                        tool=self.name,
                        message=check.get("check_name") or "",
                        file=(check.get("file_path") or "").lstrip("/") or None,
                        line=line_range[0] if line_range else None,
                        resource=check.get("resource") or None,
                        references=(guideline,) if guideline else (),
                    )
                )
        return findings
