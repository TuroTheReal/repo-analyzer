"""Tests for scoring, grading and the gate decision."""

import pytest

from repo_analyzer.core import scorer
from repo_analyzer.core.finding import Domain, Finding, Severity
from repo_analyzer.core.scorer import _grade


CRIT_AND_HIGH = frozenset({Severity.CRITICAL, Severity.HIGH})


def _finding(severity, domain=Domain.IAC, line=1) -> Finding:
    return Finding(
        rule_id=f"R{line}",
        title="t",
        severity=severity,
        domain=domain,
        tool="trivy",
        file="main.tf",
        line=line,
    )


def test_clean_scan_is_perfect_and_passes():
    result = scorer.score([], {Domain.IAC}, CRIT_AND_HIGH)
    assert result.total == 100
    assert result.grade == "A+"
    assert result.passed is True


def test_single_critical_penalizes_and_fails_gate():
    result = scorer.score([_finding(Severity.CRITICAL)], {Domain.IAC}, CRIT_AND_HIGH)
    assert result.total == 85  # 100 - 15, single scanned domain weighted at 1.0
    assert result.grade == "A-"
    assert result.passed is False


def test_high_does_not_fail_gate_when_fail_on_is_critical_only():
    result = scorer.score([_finding(Severity.HIGH)], {Domain.IAC}, frozenset({Severity.CRITICAL}))
    assert result.passed is True


def test_grade_is_worst_assessed_domain():
    # Critical in IaC (-> 85), SECRETS assessed but clean (100). Grade = worst = 85.
    findings = [_finding(Severity.CRITICAL, domain=Domain.IAC)]
    result = scorer.score(findings, {Domain.IAC, Domain.SECRETS}, CRIT_AND_HIGH)
    assert result.total == 85
    assert result.grade == "A-"
    assert {d.domain for d in result.domains} == {Domain.IAC, Domain.SECRETS}


def test_severity_counts_are_reported():
    findings = [_finding(Severity.CRITICAL, line=1), _finding(Severity.LOW, line=2)]
    result = scorer.score(findings, {Domain.IAC}, CRIT_AND_HIGH)
    assert result.counts[Severity.CRITICAL] == 1
    assert result.counts[Severity.LOW] == 1
    assert result.counts[Severity.HIGH] == 0


@pytest.mark.parametrize(
    "score,grade",
    [(100, "A+"), (95, "A+"), (94, "A"), (90, "A"), (89, "A-"), (85, "A-"),
     (80, "B+"), (50, "D"), (49, "F"), (0, "F")],
)
def test_grade_boundaries(score, grade):
    assert _grade(score) == grade


def test_adding_clean_domain_never_raises_grade():
    findings = [_finding(Severity.CRITICAL, domain=Domain.IAC)]  # IaC -> 85
    two = scorer.score(findings, {Domain.IAC, Domain.SECRETS}, CRIT_AND_HIGH)
    three = scorer.score(findings, {Domain.IAC, Domain.SECRETS, Domain.CONTAINER}, CRIT_AND_HIGH)
    # extra clean domains cannot lift the grade above the worst (IaC = 85)
    assert two.total == 85
    assert three.total == 85
    assert len(three.domains) == 3


def test_finding_in_unscanned_domain_is_still_counted():
    findings = [_finding(Severity.CRITICAL, domain=Domain.SECRETS)]
    result = scorer.score(findings, {Domain.IAC}, CRIT_AND_HIGH)
    assert {d.domain for d in result.domains} == {Domain.IAC, Domain.SECRETS}
    assert result.passed is False


def test_no_scanned_domains_is_perfect_and_passes():
    result = scorer.score([], set(), CRIT_AND_HIGH)
    assert result.total == 100
    assert result.passed is True


def test_supply_chain_is_advisory_excluded_from_headline_grade():
    # A weak supply-chain posture must NOT drag the headline grade.
    findings = [
        _finding(Severity.MEDIUM, domain=Domain.SUPPLY_CHAIN, line=1),
        _finding(Severity.MEDIUM, domain=Domain.SUPPLY_CHAIN, line=2),
        _finding(Severity.MEDIUM, domain=Domain.SUPPLY_CHAIN, line=3),
    ]
    result = scorer.score(findings, {Domain.IAC, Domain.SUPPLY_CHAIN}, CRIT_AND_HIGH)
    assert result.total == 100  # IaC clean drives the headline, supply chain ignored
    assert result.grade == "A+"
    assert result.supply_chain is not None
    assert result.supply_chain.domain is Domain.SUPPLY_CHAIN
    assert result.supply_chain.score == 88  # 100 - 3 * MEDIUM(4)
    assert result.passed is True  # capped MEDIUM never trips the critical/high gate


def test_supply_chain_is_none_when_not_assessed():
    result = scorer.score([_finding(Severity.CRITICAL)], {Domain.IAC}, CRIT_AND_HIGH)
    assert result.supply_chain is None
