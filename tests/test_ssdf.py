"""Tests for the SSDF coverage mapping and the --audit ssdf output."""

import json

from repo_analyzer import cli
from repo_analyzer.core import ssdf
from repo_analyzer.core.finding import Domain


def _by_id(assessed):
    return {c.practice.id: c for c in ssdf.coverage(assessed)}


def test_coverage_maps_assessed_domains_to_practices():
    cov = _by_id({Domain.DEPENDENCIES, Domain.SUPPLY_CHAIN})
    assert cov["PW.4"].covered and Domain.DEPENDENCIES in cov["PW.4"].covered_by
    assert cov["PS.2"].covered and Domain.SUPPLY_CHAIN in cov["PS.2"].covered_by
    assert set(cov["RV.1"].covered_by) == {Domain.DEPENDENCIES, Domain.SUPPLY_CHAIN}
    # nothing for SAST / IaC / pipeline was assessed -> gaps
    assert not cov["PW.7"].covered
    assert not cov["PW.9"].covered
    assert not cov["PW.6"].covered


def test_coverage_all_gaps_when_nothing_assessed():
    assert all(not c.covered for c in ssdf.coverage(set()))


def test_to_markdown_summarizes_and_flags_gaps():
    md = ssdf.to_markdown(ssdf.coverage({Domain.DEPENDENCIES}), "myrepo")
    assert "SSDF coverage — myrepo" in md
    assert "practices covered" in md
    assert "✅ covered" in md and "❌ gap" in md
    assert "PW.4" in md and "PW.7" in md


def test_cli_audit_ssdf_writes_coverage_report(tmp_path):
    # A grype run (dependencies domain) -> PW.4 / RV.1 covered.
    sarif = {"runs": [{"tool": {"driver": {"name": "grype"}}, "results": []}]}
    sf = tmp_path / "r.sarif"
    sf.write_text(json.dumps(sarif), encoding="utf-8")
    out = tmp_path / "out"
    code = cli.main([
        str(tmp_path), "--sarif", str(sf), "--audit", "ssdf",
        "--output-dir", str(out), "--format", "json", "--no-gate",
    ])
    assert code == cli.EXIT_OK
    report = (out / "ssdf-coverage.md").read_text(encoding="utf-8")
    assert "PW.4" in report and "✅ covered" in report
