"""Trivy runner for IaC misconfiguration scanning (``trivy config``).

Covers Terraform, CloudFormation, Kubernetes manifests, Dockerfile, Helm and
ARM, across AWS / GCP / Azure, using Trivy's built-in policy packs. We never
pass ``--exit-code`` to Trivy: a non-zero exit then means a real tool failure,
not "findings present", which we decide ourselves from the parsed output.
"""

from __future__ import annotations

import json
from pathlib import Path

from ..core.finding import Finding, Severity
from .base import Runner, RunnerError, RunnerResult, domain_for_iac_type, run_command


# First runs download Trivy's policy bundle, so allow a generous timeout.
_TIMEOUT_SECONDS = 300


class TrivyConfigRunner(Runner):
    """Wrap ``trivy config`` and emit IaC findings."""

    name = "trivy"
    binary = "trivy"

    def run(self, root: Path) -> RunnerResult:
        stdout = run_command(
            ["trivy", "config", "--format", "json", "--quiet", str(root)],
            cwd=root,
            timeout=_TIMEOUT_SECONDS,
        )
        try:
            data = json.loads(stdout or "{}")
        except json.JSONDecodeError as exc:
            raise RunnerError(f"trivy returned invalid JSON: {exc}") from exc

        # Each Result carries a Type (terraform, kubernetes, dockerfile, ...),
        # present even for clean files, so the set of types tells us which
        # domains were actually assessed.
        applicable = frozenset(domain_for_iac_type(r.get("Type")) for r in (data.get("Results") or []))
        return RunnerResult(list(self._parse(data)), applicable, raw=stdout)

    def _parse(self, data: dict) -> list[Finding]:
        """Translate Trivy's JSON into findings, routing each Result by file type."""
        findings: list[Finding] = []
        for result in data.get("Results") or []:
            target = result.get("Target")
            domain = domain_for_iac_type(result.get("Type"))
            for misconf in result.get("Misconfigurations") or []:
                if misconf.get("Status", "FAIL").upper() == "PASS":
                    continue
                cause = misconf.get("CauseMetadata") or {}
                references = tuple(misconf.get("References") or [])
                if not references and misconf.get("PrimaryURL"):
                    references = (misconf["PrimaryURL"],)

                findings.append(
                    Finding(
                        rule_id=misconf.get("AVDID") or misconf.get("ID") or "UNKNOWN",
                        title=misconf.get("Title") or misconf.get("ID") or "Misconfiguration",
                        severity=Severity.from_str(misconf.get("Severity")),
                        domain=domain,
                        tool=self.name,
                        message=misconf.get("Message") or misconf.get("Description") or "",
                        file=target,
                        line=cause.get("StartLine") or None,
                        resource=cause.get("Resource") or None,
                        remediation=misconf.get("Resolution") or None,
                        references=references,
                    )
                )
        return findings
