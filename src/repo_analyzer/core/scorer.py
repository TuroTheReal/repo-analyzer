"""Turn a list of findings into a letter grade and a gate decision.

The global grade is the **worst assessed domain**: you are as strong as your
weakest link. This is the intuitive, hard-to-game model for a security gate, a
single critical anywhere caps the headline grade, and adding a scanner for a
healthy new area can never raise it.

Only domains that were actually *assessed* (relevant files present) count. A
repo with no Kubernetes manifests is not scored on the container domain at all,
rather than shown a misleading perfect score.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

from .finding import Domain, Finding, Severity


# Points subtracted from a domain's 100 baseline per finding of each severity.
PENALTY: dict[Severity, int] = {
    Severity.CRITICAL: 15,
    Severity.HIGH: 8,
    Severity.MEDIUM: 4,
    Severity.LOW: 1,
    Severity.INFO: 0,
}


@dataclass(frozen=True)
class DomainScore:
    """Score for a single assessed security domain."""

    domain: Domain
    score: int
    findings: int


@dataclass(frozen=True)
class ScoreResult:
    """Full scoring outcome consumed by the reporters."""

    total: int
    grade: str
    passed: bool
    domains: list[DomainScore]
    counts: dict[Severity, int]
    fail_on: frozenset[Severity]
    #: Supply-chain posture (OpenSSF Scorecard), advisory: its own score, kept
    #: OUT of the headline grade so repo governance never drags the code/infra
    #: verdict. ``None`` when the supply-chain domain was not assessed.
    supply_chain: DomainScore | None = None


def _grade(score: int) -> str:
    """Map a 0-100 score to a letter grade."""
    thresholds = [
        (95, "A+"), (90, "A"), (85, "A-"),
        (80, "B+"), (75, "B"), (70, "B-"),
        (65, "C+"), (60, "C"), (55, "C-"),
        (50, "D"),
    ]
    for minimum, grade in thresholds:
        if score >= minimum:
            return grade
    return "F"


def _domain_score(findings: list[Finding]) -> int:
    """Score a single domain: 100 minus the severity penalties, floored at 0."""
    return max(0, 100 - sum(PENALTY[f.severity] for f in findings))


def score(
    findings: list[Finding],
    assessed_domains: set[Domain],
    fail_on: frozenset[Severity],
) -> ScoreResult:
    """Compute the global grade (worst assessed domain) and the gate decision.

    Args:
        findings: Deduplicated findings.
        assessed_domains: Domains actually assessed (relevant files present). A
            domain with findings is always assessed; a clean assessed domain
            scores 100; an unassessed domain is excluded entirely.
        fail_on: Severities that make the gate fail (e.g. CRITICAL + HIGH).

    Returns:
        A :class:`ScoreResult`.
    """
    by_domain: dict[Domain, list[Finding]] = {d: [] for d in assessed_domains}
    for finding in findings:
        by_domain.setdefault(finding.domain, []).append(finding)

    domain_scores = [
        DomainScore(domain=domain, score=_domain_score(by_domain[domain]), findings=len(by_domain[domain]))
        for domain in sorted(by_domain, key=lambda d: d.value)
    ]

    # Worst assessed domain drives the grade; perfect when nothing was assessed.
    # Supply chain (OpenSSF Scorecard) is advisory posture, excluded from the
    # headline so governance gaps never cap the code/infra verdict.
    gradeable = [d for d in domain_scores if d.domain is not Domain.SUPPLY_CHAIN]
    total = min((d.score for d in gradeable), default=100)
    supply_chain = next((d for d in domain_scores if d.domain is Domain.SUPPLY_CHAIN), None)

    counts = {sev: 0 for sev in Severity}
    counts.update(Counter(f.severity for f in findings))
    passed = not any(f.severity in fail_on for f in findings)
    # The headline grade must never read better than the gate: a gate-failing
    # finding caps the letter at F, so a misleading "A- but FAILED" cannot happen.
    # The numeric `total` keeps the posture score for the per-domain breakdown.
    grade = _grade(total) if passed else "F"

    return ScoreResult(
        total=total,
        grade=grade,
        passed=passed,
        domains=domain_scores,
        counts=counts,
        fail_on=fail_on,
        supply_chain=supply_chain,
    )
