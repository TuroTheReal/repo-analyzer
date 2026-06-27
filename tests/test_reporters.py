"""Tests for the reporters: valid SARIF, HTML escaping, consistent numbers."""

import json

from repo_analyzer.core import scorer
from repo_analyzer.core.finding import Domain, Finding, Severity
from repo_analyzer.report import Report
from repo_analyzer.reporters import html, json_report, markdown, sarif


def _report(findings) -> Report:
    result = scorer.score(findings, {Domain.IAC}, frozenset({Severity.CRITICAL, Severity.HIGH}))
    return Report(
        repo_name="demo",
        target="/tmp/demo",
        generated_at="2026-01-01 00:00:00 UTC",
        findings=findings,
        score=result,
        tools=["trivy"],
        duplicates_removed=0,
    )


def _finding(**kwargs) -> Finding:
    base = dict(
        rule_id="AVD-AWS-0001",
        title="open security group",
        severity=Severity.CRITICAL,
        domain=Domain.IAC,
        tool="trivy",
        file="main.tf",
        line=12,
    )
    base.update(kwargs)
    return Finding(**base)


def test_sarif_is_valid_and_maps_severity_to_level():
    report = _report([_finding()])
    doc = json.loads(sarif.render(report))
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "repo-analyzer"
    assert len(run["results"]) == 1
    assert run["results"][0]["level"] == "error"  # critical -> error
    assert run["results"][0]["properties"]["security-severity"] == "9.5"


def test_html_escapes_repo_controlled_strings():
    report = _report([_finding(title="<script>alert(1)</script>")])
    out = html.render(report)
    assert "<script>alert(1)</script>" not in out
    assert "&lt;script&gt;" in out
    assert "demo" in out


def test_markdown_and_json_agree_on_grade():
    report = _report([_finding()])
    md = markdown.render(report)
    payload = json.loads(json_report.render(report))
    assert f"Grade: {report.score.grade}" in md
    assert payload["score"]["grade"] == report.score.grade
    assert payload["score"]["passed"] is False


def test_empty_report_renders_clean():
    report = _report([])
    assert "No findings" in markdown.render(report)
    assert "No findings" in html.render(report)


def test_empty_report_sarif_and_json_are_valid():
    report = _report([])
    sarif_doc = json.loads(sarif.render(report))
    assert sarif_doc["runs"][0]["results"] == []
    assert sarif_doc["runs"][0]["tool"]["driver"]["rules"] == []
    payload = json.loads(json_report.render(report))
    assert payload["findings"] == []
    assert payload["score"]["counts"] == {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}


def test_html_drops_dangerous_url_schemes_in_references():
    report = _report([_finding(references=("javascript:alert(1)",))])
    out = html.render(report)
    assert "javascript:alert(1)" not in out
    # http(s) references are kept.
    report_ok = _report([_finding(references=("https://example.com/advisory",))])
    assert "https://example.com/advisory" in html.render(report_ok)


def test_markdown_collapses_newlines_in_tool_text():
    report = _report([_finding(message="line1\n\n## Injected heading\nline2")])
    out = markdown.render(report)
    # newlines collapsed, so the tool text can no longer start a Markdown heading
    assert "\n## Injected heading" not in out
    assert "line1 ## Injected heading line2" in out


def test_sarif_result_has_location_and_fingerprint():
    report = _report([_finding(file=None, line=None)])
    result = json.loads(sarif.render(report))["runs"][0]["results"][0]
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "."
    assert "partialFingerprints" in result


def test_report_flags_not_assessed_project_domains():
    from repo_analyzer.reporters._common import build_context

    # _report scores over {IAC} only, so the other project domains are "not assessed".
    ctx = build_context(_report([_finding()]))
    assert "IaC" not in ctx["not_assessed"]
    assert "Container" in ctx["not_assessed"]
    assert "Secrets" in ctx["not_assessed"]
    assert "Dependencies" in ctx["not_assessed"]


def test_markdown_rule_id_and_resource_cannot_inject_headings():
    report = _report([_finding(rule_id="R\n## INJ", resource="res\n### INJ2")])
    out = markdown.render(report)
    assert "\n## INJ" not in out
    assert "\n### INJ2" not in out
