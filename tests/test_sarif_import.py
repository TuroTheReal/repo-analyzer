"""Tests for external SARIF ingestion: driver routing, severity mapping, CLI mode."""

import json

import pytest

from repo_analyzer import cli
from repo_analyzer.core.finding import Domain
from repo_analyzer.core.finding import Severity as Sev
from repo_analyzer.core.sarif_import import SarifError, import_sarif


def _result(rule_id, *, level=None, security_severity=None, text="msg", uri=None, line=None):
    result = {"ruleId": rule_id, "message": {"text": text}}
    if level is not None:
        result["level"] = level
    if security_severity is not None:
        result["properties"] = {"security-severity": security_severity}
    if uri is not None:
        result["locations"] = [{"physicalLocation": {"artifactLocation": {"uri": uri}, "region": {"startLine": line}}}]
    return result


def _sarif(*runs):
    return {"runs": [{"tool": {"driver": {"name": name}}, "results": results} for name, results in runs]}


def _write(tmp_path, sarif):
    path = tmp_path / "report.sarif"
    path.write_text(json.dumps(sarif), encoding="utf-8")
    return path


def test_routes_by_driver_and_maps_severity(tmp_path):
    sarif = _sarif(
        ("Semgrep", [_result("py.sqli", level="error", text="SQL injection", uri="app.py", line=10)]),
        ("Trivy", [_result("AVD-1", security_severity="9.5", text="crit", uri="main.tf", line=3)]),
        ("weirdtool", []),  # unknown driver, zero results
    )
    findings, assessed, tools = import_sarif([_write(tmp_path, sarif)])

    routed = {f.rule_id: (f.domain, f.severity) for f in findings}
    assert routed == {
        "py.sqli": (Domain.CODE, Sev.HIGH),       # semgrep -> CODE, level error -> HIGH
        "AVD-1": (Domain.IAC, Sev.CRITICAL),       # trivy -> IaC, security-severity 9.5 -> CRITICAL
    }
    # a zero-result run still marks its domain assessed (unknown driver -> CODE)
    assert assessed == {Domain.CODE, Domain.IAC}
    assert tools == ["Semgrep", "Trivy", "weirdtool"]
    sqli = next(f for f in findings if f.rule_id == "py.sqli")
    assert sqli.file == "app.py" and sqli.line == 10


def test_security_severity_bands(tmp_path):
    sarif = _sarif(("Trivy", [
        _result("c", security_severity="9.0"),
        _result("h", security_severity="7.0"),
        _result("m", security_severity="4.0"),
        _result("l", security_severity="0.1"),
    ]))
    findings, _, _ = import_sarif([_write(tmp_path, sarif)])
    assert {f.rule_id: f.severity for f in findings} == {
        "c": Sev.CRITICAL, "h": Sev.HIGH, "m": Sev.MEDIUM, "l": Sev.LOW,
    }


def test_unknown_driver_falls_back_to_code(tmp_path):
    findings, assessed, _ = import_sarif([_write(tmp_path, _sarif(("mysterylinter", [_result("X", level="warning")])))])
    assert findings[0].domain is Domain.CODE
    assert assessed == {Domain.CODE}


def test_malformed_sarif_raises(tmp_path):
    bad = tmp_path / "bad.sarif"
    bad.write_text("{not json", encoding="utf-8")
    with pytest.raises(SarifError):
        import_sarif([bad])


def test_missing_file_raises(tmp_path):
    with pytest.raises(SarifError):
        import_sarif([tmp_path / "nope.sarif"])


def test_cli_sarif_mode_grades_external_report(tmp_path):
    sarif = _sarif(("Trivy", [_result("AVD-1", security_severity="9.5", text="crit", uri="main.tf", line=1)]))
    sf = _write(tmp_path, sarif)
    out = tmp_path / "out"
    code = cli.main([str(tmp_path), "--sarif", str(sf), "--output-dir", str(out), "--format", "json"])
    assert code == cli.EXIT_GATE_FAILED  # a critical fails the default gate
    payload = json.loads((out / "report.json").read_text(encoding="utf-8"))
    assert any(d["domain"] == "iac" for d in payload["score"]["domains"])
    assert payload["tools"] == ["Trivy"]
