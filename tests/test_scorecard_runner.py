"""Tests for the OpenSSF Scorecard runner: severity capping, parsing, applicability."""

from repo_analyzer.core.finding import Domain
from repo_analyzer.core.finding import Severity as Sev
from repo_analyzer.runners.scorecard import ScorecardRunner


def _check(name, score, short="short", url="http://example/doc"):
    return {"name": name, "score": score, "reason": "why", "documentation": {"short": short, "url": url}}


def test_severity_is_capped_at_medium():
    sev = ScorecardRunner._severity
    assert sev(0) is Sev.MEDIUM
    assert sev(4) is Sev.MEDIUM
    assert sev(5) is Sev.LOW
    assert sev(9) is Sev.LOW
    assert sev(10) is None   # perfect -> not a finding
    assert sev(-1) is None   # inconclusive -> not a finding
    assert sev("x") is None  # malformed -> skipped


def test_parse_emits_supply_chain_findings_skipping_perfect_and_inconclusive():
    data = {
        "checks": [
            _check("Branch-Protection", 2),
            _check("Pinned-Dependencies", 7),
            _check("Token-Permissions", 10),  # perfect -> skipped
            _check("Fuzzing", -1),            # inconclusive -> skipped
        ]
    }
    findings = ScorecardRunner()._parse(data)
    assert len(findings) == 2
    assert all(f.domain is Domain.SUPPLY_CHAIN and f.tool == "scorecard" for f in findings)
    by_id = {f.rule_id: f for f in findings}
    assert by_id["Branch-Protection"].severity is Sev.MEDIUM
    assert by_id["Pinned-Dependencies"].severity is Sev.LOW
    assert by_id["Branch-Protection"].references == ("http://example/doc",)


def test_parse_empty_when_no_checks():
    assert ScorecardRunner()._parse({}) == []


def test_run_not_assessed_on_non_git_folder(tmp_path):
    # Not a GitHub repo root -> Scorecard is not applicable -> domain unassessed.
    result = ScorecardRunner().run(tmp_path)
    assert result.findings == []
    assert result.applicable_domains == frozenset()
