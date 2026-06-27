"""Tests for deduplication and ordering in the merger."""

from repo_analyzer.core import merger
from repo_analyzer.core.finding import Domain, Finding, Severity


def _finding(rule_id, severity, file="main.tf", line=1) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=rule_id,
        severity=severity,
        domain=Domain.IAC,
        tool="trivy",
        file=file,
        line=line,
    )


def test_duplicate_is_dropped_keeping_highest_severity():
    low = _finding("R1", Severity.LOW)
    high = _finding("R1", Severity.HIGH)
    result = merger.merge([low], [high])
    assert len(result.findings) == 1
    assert result.findings[0].severity is Severity.HIGH
    assert result.duplicates_removed == 1


def test_distinct_findings_are_all_kept_and_sorted_by_severity():
    result = merger.merge(
        [_finding("R1", Severity.LOW, line=1)],
        [_finding("R2", Severity.CRITICAL, line=2)],
        [_finding("R3", Severity.MEDIUM, line=3)],
    )
    assert [f.severity for f in result.findings] == [
        Severity.CRITICAL,
        Severity.MEDIUM,
        Severity.LOW,
    ]
    assert result.duplicates_removed == 0
