"""grype runner for dependency vulnerability scanning (domain: DEPENDENCIES).

Scans the filesystem for packages and reports known CVEs. grype exits 0 unless
``--fail-on`` is set (we never set it), so a non-zero exit means a real failure.
"""

from __future__ import annotations

import json
from pathlib import Path

from ..core.finding import Domain, Finding, Severity
from .base import Runner, RunnerError, RunnerResult, relative_to_root, run_command


# First run downloads grype's vulnerability DB, so allow a generous timeout.
_TIMEOUT_SECONDS = 300

# Dependency manifests whose presence means the dependencies domain is assessable.
_MANIFESTS = (
    "requirements.txt", "poetry.lock", "Pipfile.lock", "package.json", "package-lock.json",
    "yarn.lock", "pnpm-lock.yaml", "go.mod", "go.sum", "Gemfile.lock", "Cargo.lock",
    "pom.xml", "build.gradle", "composer.lock",
)


class GrypeRunner(Runner):
    """Wrap ``grype dir:<root>`` and emit dependency-CVE findings."""

    name = "grype"
    binary = "grype"

    def run(self, root: Path) -> RunnerResult:
        stdout = run_command(
            ["grype", f"dir:{root}", "-o", "json", "-q"],
            cwd=root,
            timeout=_TIMEOUT_SECONDS,
        )
        try:
            data = json.loads(stdout or "{}")
        except json.JSONDecodeError as exc:
            raise RunnerError(f"grype returned invalid JSON: {exc}") from exc

        findings = list(self._parse(data, root))
        # grype's matches-only output cannot tell "clean" from "no deps", so the
        # domain is assessed when there are matches or a dependency manifest.
        assessed = bool(data.get("matches")) or _has_manifests(root)
        return RunnerResult(findings, frozenset({Domain.DEPENDENCIES}) if assessed else frozenset())

    def _parse(self, data: dict, root: Path) -> list[Finding]:
        findings: list[Finding] = []
        for match in data.get("matches") or []:
            vuln = match.get("vulnerability") or {}
            artifact = match.get("artifact") or {}
            package = artifact.get("name") or "unknown"
            version = artifact.get("version") or ""
            fixed = (vuln.get("fix") or {}).get("versions") or []
            locations = artifact.get("locations") or []
            data_source = vuln.get("dataSource")

            findings.append(
                Finding(
                    rule_id=vuln.get("id") or "UNKNOWN",
                    title=f"{package} {version}".strip(),
                    severity=Severity.from_str(vuln.get("severity")),
                    domain=Domain.DEPENDENCIES,
                    tool=self.name,
                    message=(vuln.get("description") or f"Vulnerable dependency {package} {version}").strip(),
                    file=relative_to_root(locations[0].get("path"), root) if locations else None,
                    resource=f"{package}@{version}" if version else package,
                    remediation=f"Upgrade {package} to {fixed[0]}" if fixed else None,
                    references=(data_source,) if data_source else (),
                )
            )
        return findings


def _has_manifests(root: Path) -> bool:
    """Whether the repo contains any dependency manifest grype understands."""
    return any(next(root.rglob(name), None) is not None for name in _MANIFESTS)
