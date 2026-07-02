"""Import findings from external SARIF.

Any scanner that emits SARIF (Semgrep, CodeQL, Trivy, Snyk, Bandit...) can feed
the same normalize -> merge -> score -> report pipeline as the built-in runners.
Findings are routed to a :class:`~repo_analyzer.core.finding.Domain` by the SARIF
tool (driver) name; an unrecognised tool falls back to CODE.
"""

from __future__ import annotations

import json
from pathlib import Path

from .finding import Domain, Finding, Severity


# SARIF driver name (lower-cased) -> domain.
_DRIVER_DOMAIN: dict[str, Domain] = {
    "trivy": Domain.IAC,
    "checkov": Domain.IAC,
    "kics": Domain.IAC,
    "terrascan": Domain.IAC,
    "tfsec": Domain.IAC,
    "hadolint": Domain.CONTAINER,
    "dockle": Domain.CONTAINER,
    "grype": Domain.DEPENDENCIES,
    "osv-scanner": Domain.DEPENDENCIES,
    "gitleaks": Domain.SECRETS,
    "trufflehog": Domain.SECRETS,
    "zizmor": Domain.PIPELINE,
    "actionlint": Domain.PIPELINE,
    "scorecard": Domain.SUPPLY_CHAIN,
    "semgrep": Domain.CODE,
    "bandit": Domain.CODE,
    "codeql": Domain.CODE,
    "sonarqube": Domain.CODE,
    "eslint": Domain.CODE,
}


class SarifError(ValueError):
    """Raised when a SARIF file is missing or malformed."""


def _domain_for_driver(name: str) -> Domain:
    return _DRIVER_DOMAIN.get(name.strip().lower(), Domain.CODE)


def _severity(result: dict) -> Severity:
    """Severity from a SARIF result: prefer ``security-severity`` (CVSS), else level."""
    raw = (result.get("properties") or {}).get("security-severity")
    try:
        score = float(raw) if raw is not None else None
    except (TypeError, ValueError):
        score = None
    if score is not None:
        if score >= 9.0:
            return Severity.CRITICAL
        if score >= 7.0:
            return Severity.HIGH
        if score >= 4.0:
            return Severity.MEDIUM
        return Severity.LOW if score > 0.0 else Severity.INFO
    # SARIF level: error/warning/note/none -> mapped via the alias table.
    return Severity.from_str(result.get("level"))


def _location(result: dict) -> tuple[str | None, int | None]:
    locations = result.get("locations") or []
    phys = (locations[0] or {}).get("physicalLocation") or {} if locations else {}
    uri = ((phys.get("artifactLocation") or {}).get("uri")) or None
    line = (phys.get("region") or {}).get("startLine")
    return uri, (line if isinstance(line, int) else None)


def import_sarif(paths: list[Path]) -> tuple[list[Finding], set[Domain], list[str]]:
    """Parse SARIF file(s) into findings, the domains present, and the tool names.

    A domain is *assessed* if any run's tool maps to it, even with zero results,
    so a clean external scan scores that domain 100 rather than dropping it.

    Raises:
        SarifError: if a file cannot be read or is not valid JSON.
    """
    findings: list[Finding] = []
    assessed: set[Domain] = set()
    tools: list[str] = []

    for path in paths:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise SarifError(f"cannot read SARIF {path}: {exc}") from exc

        for run in data.get("runs") or []:
            driver = (((run.get("tool") or {}).get("driver")) or {}).get("name") or "sarif"
            domain = _domain_for_driver(driver)
            assessed.add(domain)
            if driver not in tools:
                tools.append(driver)
            for result in run.get("results") or []:
                message = ((result.get("message") or {}).get("text")) or ""
                rule_id = result.get("ruleId") or "sarif"
                file, line = _location(result)
                findings.append(
                    Finding(
                        rule_id=rule_id,
                        title=message.splitlines()[0] if message else rule_id,
                        severity=_severity(result),
                        domain=domain,
                        tool=driver,
                        message=message,
                        file=file,
                        line=line,
                    )
                )
    return findings, assessed, tools
