"""SARIF 2.1.0 reporter.

GitHub code scanning ingests this file and renders each finding inline on the
PR diff and in the repo Security tab. The ``security-severity`` property is what
GitHub uses to rank findings, so we set it per severity.
"""

from __future__ import annotations

import hashlib
import json

from .. import __version__
from ..core.finding import Finding, Severity
from ..report import Report


SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"
INFORMATION_URI = "https://github.com/TuroTheReal/repo-analyzer"

# SARIF only has error / warning / note; map our five severities onto them.
_LEVEL: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

# GitHub ranks findings by this numeric CVSS-like score.
_SECURITY_SEVERITY: dict[Severity, str] = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.0",
    Severity.LOW: "2.0",
    Severity.INFO: "0.0",
}


def _rule(finding: Finding) -> dict:
    rule: dict = {
        "id": finding.rule_id,
        "name": finding.rule_id,
        "shortDescription": {"text": finding.title},
        "properties": {
            "security-severity": _SECURITY_SEVERITY[finding.severity],
            "tags": [finding.domain.value, finding.tool],
        },
    }
    if finding.references:
        rule["helpUri"] = finding.references[0]
    if finding.remediation:
        rule["help"] = {"text": finding.remediation}
    return rule


def _fingerprint(finding: Finding) -> str:
    """Stable identity for cross-commit alert tracking.

    Deliberately excludes the line number so inserting code above a finding
    does not close the old alert and open a new one.
    """
    raw = "|".join((finding.rule_id, finding.file or "", finding.resource or ""))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def _result(finding: Finding) -> dict:
    # GitHub code scanning needs every result to carry a location to render it
    # on the diff; fall back to the repo root for location-less findings.
    location: dict = {"artifactLocation": {"uri": finding.file or "."}}
    if finding.line:
        location["region"] = {"startLine": finding.line}
    return {
        "ruleId": finding.rule_id,
        "level": _LEVEL[finding.severity],
        "message": {"text": finding.message or finding.title},
        "locations": [{"physicalLocation": location}],
        "partialFingerprints": {"repoAnalyzer/v1": _fingerprint(finding)},
        "properties": {
            "security-severity": _SECURITY_SEVERITY[finding.severity],
            "tool": finding.tool,
            "domain": finding.domain.value,
        },
    }


def render(report: Report) -> str:
    """Render the report as a SARIF 2.1.0 document."""
    rules: dict[str, dict] = {}
    results: list[dict] = []
    for finding in report.findings:
        rules.setdefault(finding.rule_id, _rule(finding))
        results.append(_result(finding))

    document = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "repo-analyzer",
                        "version": __version__,
                        "informationUri": INFORMATION_URI,
                        "rules": list(rules.values()),
                    }
                },
                "automationDetails": {"id": "repo-analyzer"},
                "results": results,
            }
        ],
    }
    return json.dumps(document, indent=2, ensure_ascii=False)
