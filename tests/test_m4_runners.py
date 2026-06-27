"""Parsing tests for the M4 pipeline runners (zizmor, actionlint).

Both expose a pure ``_parse`` so we test the mapping on synthetic output without
invoking the real binary.
"""

from repo_analyzer.core.finding import Domain, Severity
from repo_analyzer.runners.actionlint import ActionlintRunner
from repo_analyzer.runners.zizmor import ZizmorRunner


def test_zizmor_maps_pipeline_findings(tmp_path):
    path = str(tmp_path / ".github" / "workflows" / "ci.yml")
    data = [
        {
            "ident": "unpinned-uses",
            "desc": "unpinned action reference",
            "url": "https://docs.zizmor.sh/audits/#unpinned-uses",
            "determinations": {"confidence": "High", "severity": "High"},
            "locations": [
                {
                    "symbolic": {"key": {"Local": {"given_path": path}}},
                    "concrete": {"location": {"start_point": {"row": 15}}},
                }
            ],
        }
    ]
    f = ZizmorRunner()._parse(data, tmp_path)[0]
    assert f.domain is Domain.PIPELINE
    assert f.severity is Severity.HIGH
    assert f.rule_id == "unpinned-uses"
    assert f.file == ".github/workflows/ci.yml"
    assert f.line == 16  # zizmor rows are 0-based, so row 15 -> line 16
    assert f.references[0].startswith("https://")


def test_zizmor_severity_mapping():
    def one(sev):
        return [{"ident": "x", "desc": "d", "determinations": {"severity": sev}, "locations": []}]

    runner = ZizmorRunner()
    assert runner._parse(one("Informational"))[0].severity is Severity.INFO
    assert runner._parse(one("Low"))[0].severity is Severity.LOW
    assert runner._parse(one("Medium"))[0].severity is Severity.MEDIUM
    assert runner._parse(one("Unknown"))[0].severity is Severity.INFO


def test_actionlint_maps_lint_as_low_pipeline():
    data = [{"message": "unknown runner label", "filepath": ".github/workflows/ci.yml",
             "line": 7, "column": 9, "kind": "runner-label"}]
    f = ActionlintRunner()._parse(data)[0]
    assert f.domain is Domain.PIPELINE
    assert f.severity is Severity.LOW
    assert f.rule_id == "runner-label"
    assert f.file == ".github/workflows/ci.yml"
    assert f.line == 7


def test_pipeline_runners_handle_empty():
    assert ZizmorRunner()._parse([]) == []
    assert ActionlintRunner()._parse([]) == []
