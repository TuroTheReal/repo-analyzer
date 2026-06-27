"""Canonical JSON reporter: the machine-readable source of truth.

Drives the badge, the HTML dashboard data and any downstream automation.
"""

from __future__ import annotations

import json

from ..core.finding import Finding
from ..report import Report


def _finding_to_dict(finding: Finding) -> dict:
    return {
        "rule_id": finding.rule_id,
        "title": finding.title,
        "severity": finding.severity.value,
        "domain": finding.domain.value,
        "tool": finding.tool,
        "message": finding.message,
        "file": finding.file,
        "line": finding.line,
        "resource": finding.resource,
        "remediation": finding.remediation,
        "references": list(finding.references),
    }


def render(report: Report) -> str:
    """Serialize the whole report to indented JSON."""
    score = report.score
    payload = {
        "repo": report.repo_name,
        "target": report.target,
        "generated_at": report.generated_at,
        "tools": report.tools,
        "score": {
            "total": score.total,
            "grade": score.grade,
            "passed": score.passed,
            "fail_on": sorted(s.value for s in score.fail_on),
            "counts": {sev.value: count for sev, count in score.counts.items()},
            "domains": [
                {"domain": d.domain.value, "score": d.score, "findings": d.findings}
                for d in score.domains
            ],
        },
        "duplicates_removed": report.duplicates_removed,
        "findings": [_finding_to_dict(f) for f in report.findings],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)
