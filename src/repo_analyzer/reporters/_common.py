"""Shared view helpers for the human-readable reporters (Markdown, HTML).

Builds one context dict from a :class:`~repo_analyzer.report.Report` so both
renderers display identical numbers and ordering. The HTML reporter also uses
the precomputed SVG geometry (grade ring, severity donut) and the per-axis
grouping (Project / CI/CD / Repo) so the template stays declarative.
"""

from __future__ import annotations

import math

from ..core.finding import Domain, Severity
from ..core.scorer import _grade as _grade_letter
from ..report import Report


# Display order and per-severity presentation metadata. The palette is a
# warmth/intensity ramp (cool=mild -> warm/saturated=critical) that avoids the
# clichu00e9 green/red, drawn from the portfolio accent palette.
SEVERITY_ORDER: tuple[Severity, ...] = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
)

SEVERITY_META: dict[Severity, dict[str, str]] = {
    Severity.CRITICAL: {"label": "Critical", "emoji": "🔴", "color": "#fb2e6b"},
    Severity.HIGH: {"label": "High", "emoji": "🟠", "color": "#ff7a5c"},
    Severity.MEDIUM: {"label": "Medium", "emoji": "🟡", "color": "#ffe23d"},
    Severity.LOW: {"label": "Low", "emoji": "🔵", "color": "#5b8def"},
    Severity.INFO: {"label": "Info", "emoji": "⚪", "color": "#8b95a7"},
}

DOMAIN_LABEL: dict[Domain, str] = {
    Domain.IAC: "IaC",
    Domain.CONTAINER: "Container",
    Domain.SECRETS: "Secrets",
    Domain.DEPENDENCIES: "Dependencies",
    Domain.PIPELINE: "Pipeline",
    Domain.SUPPLY_CHAIN: "Supply chain",
}

# Which dashboard tab (axis) a domain belongs to.
AXIS_OF: dict[Domain, str] = {
    Domain.IAC: "project",
    Domain.CONTAINER: "project",
    Domain.SECRETS: "project",
    Domain.DEPENDENCIES: "project",
    Domain.PIPELINE: "ci",
    Domain.SUPPLY_CHAIN: "repo",
}

# Domains belonging to the "Project" axis (what the current scanners assess).
PROJECT_DOMAINS: tuple[Domain, ...] = (Domain.IAC, Domain.CONTAINER, Domain.SECRETS, Domain.DEPENDENCIES)

# Deterministic next-step when a tool gives no remediation of its own (no LLM).
_DOMAIN_HINT: dict[Domain, str] = {
    Domain.IAC: "Apply the secure configuration from the rule reference.",
    Domain.SECRETS: "Rotate the credential and purge it from git history.",
    Domain.DEPENDENCIES: "Upgrade to a patched version, or assess exposure if no fix exists.",
    Domain.CONTAINER: "Apply the Dockerfile best practice from the rule reference.",
    Domain.PIPELINE: "Harden the workflow per the rule guidance.",
    Domain.SUPPLY_CHAIN: "Close the supply-chain gap per the rule guidance.",
}

_RING_RADIUS = 54
_DONUT_RADIUS = 64


def grade_color(grade: str) -> str:
    """Badge colour for a letter grade. Green (good) -> red (bad), refined tones,
    sharing the severity ramp so colours mean the same thing across the report."""
    if grade.startswith("A"):
        return "#2fdca5"  # metallic mint
    if grade.startswith("B"):
        return "#9bd64a"  # lime
    if grade.startswith("C"):
        return "#ffe23d"  # bright yellow
    if grade.startswith("D"):
        return "#ff7a5c"  # coral
    return "#fb2e6b"  # raspberry (F / failing)


def grade_caption(grade: str) -> str:
    """One-line verdict so the grade is unambiguous (A good, F bad)."""
    if grade.startswith("A"):
        return "Strong security posture"
    if grade.startswith("B"):
        return "Good, minor issues"
    if grade.startswith("C"):
        return "Needs attention"
    if grade.startswith("D"):
        return "Weak, several issues"
    return "Failing, serious issues"


def _ring(total: int) -> dict:
    """Geometry for the circular grade gauge (an arc proportional to the score)."""
    circ = 2 * math.pi * _RING_RADIUS
    return {"radius": _RING_RADIUS, "circ": round(circ, 2), "dash": round(circ * total / 100, 2)}


def _donut(counts: list[dict], total_findings: int) -> dict:
    """Stacked-arc geometry for the severity-distribution donut."""
    circ = 2 * math.pi * _DONUT_RADIUS
    segments: list[dict] = []
    offset = 0.0
    for entry in counts:
        if entry["count"] <= 0 or total_findings <= 0:
            continue
        length = circ * entry["count"] / total_findings
        segments.append(
            {"color": entry["color"], "dash": round(length, 2), "gap": round(circ - length, 2), "offset": round(-offset, 2)}
        )
        offset += length
    return {"radius": _DONUT_RADIUS, "circ": round(circ, 2), "segments": segments}


def _action(remediation: str | None, domain: Domain) -> str:
    """The next-step shown per finding: the tool's remediation, else a static hint."""
    return remediation or _DOMAIN_HINT.get(domain, "See the rule reference.")


def build_context(report: Report) -> dict:
    """Assemble the rendering context shared by Markdown and HTML."""
    score = report.score

    counts = [
        {
            "value": sev.value,
            "label": SEVERITY_META[sev]["label"],
            "emoji": SEVERITY_META[sev]["emoji"],
            "color": SEVERITY_META[sev]["color"],
            "count": score.counts.get(sev, 0),
        }
        for sev in SEVERITY_ORDER
    ]

    domains = [
        {
            "label": DOMAIN_LABEL[d.domain],
            "score": d.score,
            "findings": d.findings,
            "color": grade_color(_grade_letter(d.score)),
        }
        # Most critical first: lowest score leads, name as tiebreak.
        for d in sorted(score.domains, key=lambda x: (x.score, x.domain.value))
    ]

    groups = []
    for sev in SEVERITY_ORDER:
        items = [f for f in report.findings if f.severity is sev]
        if items:
            groups.append(
                {
                    "label": SEVERITY_META[sev]["label"],
                    "emoji": SEVERITY_META[sev]["emoji"],
                    "color": SEVERITY_META[sev]["color"],
                    "findings": items,
                }
            )

    cards = [
        {
            "sev": f.severity.value,
            "sev_label": SEVERITY_META[f.severity]["label"],
            "color": SEVERITY_META[f.severity]["color"],
            "axis": AXIS_OF.get(f.domain, "project"),
            "rule_id": f.rule_id,
            "title": f.title,
            "file": f.file,
            "line": f.line,
            "resource": f.resource,
            "message": f.message,
            "action": _action(f.remediation, f.domain),
            "tool": f.tool,
            "domain": DOMAIN_LABEL.get(f.domain, f.domain.value),
            "references": list(f.references),
        }
        for f in report.findings
    ]

    assessed = {d.domain for d in score.domains}
    not_assessed = [DOMAIN_LABEL[d] for d in PROJECT_DOMAINS if d not in assessed]

    return {
        "repo_name": report.repo_name,
        "target": report.target,
        "generated_at": report.generated_at,
        "tools": ", ".join(report.tools) if report.tools else "none",
        "raw_tools": report.raw_tools,
        "duplicates_removed": report.duplicates_removed,
        "total": score.total,
        "grade": score.grade,
        "grade_color": grade_color(score.grade),
        "grade_caption": grade_caption(score.grade),
        "passed": score.passed,
        "gate_status": "PASSED" if score.passed else "FAILED",
        "fail_on": ", ".join(sorted(s.value for s in score.fail_on)),
        "total_findings": len(report.findings),
        "counts": counts,
        "domains": domains,
        "groups": groups,
        "cards": cards,
        "project_cards": [c for c in cards if c["axis"] == "project"],
        "ci_cards": [c for c in cards if c["axis"] == "ci"],
        "repo_cards": [c for c in cards if c["axis"] == "repo"],
        "not_assessed": not_assessed,
        "ring": _ring(score.total),
        "donut": _donut(counts, len(report.findings)),
    }
