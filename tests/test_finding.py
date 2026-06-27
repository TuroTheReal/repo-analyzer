"""Tests for the Finding model: severity parsing, ordering, dedup identity."""

from repo_analyzer.core.finding import Domain, Finding, Severity


def _finding(**kwargs) -> Finding:
    base = dict(
        rule_id="R1",
        title="t",
        severity=Severity.HIGH,
        domain=Domain.IAC,
        tool="trivy",
    )
    base.update(kwargs)
    return Finding(**base)


def test_severity_from_str_normalizes_aliases():
    assert Severity.from_str("CRITICAL") is Severity.CRITICAL
    assert Severity.from_str("moderate") is Severity.MEDIUM
    assert Severity.from_str("warning") is Severity.MEDIUM
    assert Severity.from_str("error") is Severity.HIGH


def test_severity_from_str_falls_back_on_unknown_or_empty():
    assert Severity.from_str(None) is Severity.MEDIUM
    assert Severity.from_str("banana") is Severity.MEDIUM
    assert Severity.from_str("banana", default=Severity.LOW) is Severity.LOW


def test_severity_ordering():
    assert Severity.CRITICAL > Severity.HIGH > Severity.MEDIUM > Severity.LOW > Severity.INFO
    assert max(Severity.LOW, Severity.CRITICAL) is Severity.CRITICAL


def test_dedup_key_matches_same_location_case_insensitively():
    a = _finding(rule_id="CKV_AWS_19", file="Main.tf", line=3, resource="aws_s3_bucket.x")
    b = _finding(rule_id="ckv_aws_19", file="main.tf", line=3, resource="AWS_S3_BUCKET.X")
    assert a.dedup_key == b.dedup_key


def test_dedup_key_differs_on_line():
    a = _finding(rule_id="R", file="main.tf", line=3)
    b = _finding(rule_id="R", file="main.tf", line=4)
    assert a.dedup_key != b.dedup_key


def test_all_aliases_map_to_expected_severities():
    assert Severity.from_str("note") is Severity.LOW
    assert Severity.from_str("negligible") is Severity.LOW
    assert Severity.from_str("unknown") is Severity.INFO
    assert Severity.from_str("none") is Severity.INFO
    assert Severity.from_str(" Moderate ") is Severity.MEDIUM


def test_try_parse_returns_none_for_unknown_or_empty():
    assert Severity.try_parse("banana") is None
    assert Severity.try_parse("") is None
    assert Severity.try_parse(None) is None
    assert Severity.try_parse("CRITICAL") is Severity.CRITICAL
    assert Severity.try_parse("moderate") is Severity.MEDIUM
