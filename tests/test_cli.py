"""End-to-end tests for the CLI gate: exit codes and argument handling.

Uses a fake runner (monkeypatched into ALL_RUNNERS) so no real Trivy is needed
and the findings are controlled.
"""

import json

from repo_analyzer import cli
from repo_analyzer.core.finding import Domain, Finding
from repo_analyzer.core.finding import Severity as Sev
from repo_analyzer.runners.base import RunnerError, RunnerResult


def _finding(severity, line=1) -> Finding:
    return Finding(
        rule_id=f"R{line}",
        title="t",
        severity=severity,
        domain=Domain.IAC,
        tool="fake",
        file="main.tf",
        line=line,
    )


def _make_runner(findings, available=True, raises=False, applicable_domains=frozenset({Domain.IAC})):
    class FakeRunner:
        name = "fake"
        binary = "fake"

        def is_available(self):
            return available

        def run(self, root):
            if raises:
                raise RunnerError("boom")
            return RunnerResult(findings, applicable_domains)

    return FakeRunner


def _run(monkeypatch, tmp_path, findings, extra=None, available=True, raises=False):
    monkeypatch.setattr(cli, "ALL_RUNNERS", (_make_runner(findings, available, raises),))
    out = tmp_path / "out"
    argv = [str(tmp_path), "--output-dir", str(out)] + (extra or [])
    return cli.main(argv), out


def test_missing_directory_returns_env_error(tmp_path):
    assert cli.main([str(tmp_path / "nope")]) == cli.EXIT_ENV_ERROR


def test_no_available_scanner_returns_env_error(monkeypatch, tmp_path):
    code, _ = _run(monkeypatch, tmp_path, [], available=False)
    assert code == cli.EXIT_ENV_ERROR


def test_sole_runner_failure_returns_env_error(monkeypatch, tmp_path):
    code, _ = _run(monkeypatch, tmp_path, [], raises=True)
    assert code == cli.EXIT_ENV_ERROR


def test_critical_finding_fails_gate(monkeypatch, tmp_path):
    code, out = _run(monkeypatch, tmp_path, [_finding(Sev.CRITICAL)])
    assert code == cli.EXIT_GATE_FAILED
    assert (out / "report.sarif").exists()
    assert (out / "report.html").exists()


def test_low_finding_passes_gate(monkeypatch, tmp_path):
    code, _ = _run(monkeypatch, tmp_path, [_finding(Sev.LOW)])
    assert code == cli.EXIT_OK


def test_no_gate_forces_pass_even_with_critical(monkeypatch, tmp_path):
    code, _ = _run(monkeypatch, tmp_path, [_finding(Sev.CRITICAL)], extra=["--no-gate"])
    assert code == cli.EXIT_OK


def test_unknown_fail_on_severity_is_rejected(monkeypatch, tmp_path):
    code, _ = _run(monkeypatch, tmp_path, [_finding(Sev.LOW)], extra=["--fail-on", "crtical"])
    assert code == cli.EXIT_ENV_ERROR


def test_empty_fail_on_is_rejected_not_a_silent_bypass(monkeypatch, tmp_path):
    # "," is truthy but yields no severities; must not disable the gate.
    code, _ = _run(monkeypatch, tmp_path, [_finding(Sev.CRITICAL)], extra=["--fail-on", ","])
    assert code == cli.EXIT_ENV_ERROR


def test_all_invalid_format_is_rejected(monkeypatch, tmp_path):
    code, _ = _run(monkeypatch, tmp_path, [_finding(Sev.LOW)], extra=["--format", "xml,pdf"])
    assert code == cli.EXIT_ENV_ERROR


def test_uppercase_format_is_accepted(monkeypatch, tmp_path):
    code, out = _run(monkeypatch, tmp_path, [_finding(Sev.LOW)], extra=["--format", "SARIF"])
    assert code == cli.EXIT_OK
    assert (out / "report.sarif").exists()


def test_config_flag_loads_the_named_file(monkeypatch, tmp_path):
    # A custom-named config raising the threshold to LOW must actually be loaded,
    # so a LOW finding fails the gate (proves --config honors the file path).
    cfg = tmp_path / "strict.yml"
    cfg.write_text("gate:\n  fail_on: [low]\n", encoding="utf-8")
    monkeypatch.setattr(cli, "ALL_RUNNERS", (_make_runner([_finding(Sev.LOW)]),))
    code = cli.main([str(tmp_path), "--output-dir", str(tmp_path / "o"), "--config", str(cfg)])
    assert code == cli.EXIT_GATE_FAILED


def test_malformed_config_returns_env_error(monkeypatch, tmp_path):
    (tmp_path / ".repo-analyzer.yml").write_text("gate: [unclosed", encoding="utf-8")
    code, _ = _run(monkeypatch, tmp_path, [_finding(Sev.LOW)])
    assert code == cli.EXIT_ENV_ERROR


def test_is_skipped_matches_segment_and_prefix():
    skips = (".git", "node_modules", "tests/fixtures")
    assert cli._is_skipped("node_modules/x/y.js", skips) is True
    assert cli._is_skipped("tests/fixtures/bad.tf", skips) is True
    assert cli._is_skipped("src/app.py", skips) is False
    assert cli._is_skipped(None, skips) is False
    assert cli._is_skipped("tests/unit/test_x.py", skips) is False
    # multi-segment entries now match anywhere (absolute + nested), not just at root
    assert cli._is_skipped("/Users/x/repo/tests/fixtures/bad.tf", skips) is True
    assert cli._is_skipped("a/tests/fixtures/bad.tf", skips) is True
    # but a partial segment name must not match
    assert cli._is_skipped("tests/fixtures-extra/x.tf", skips) is False
    # dot-prefixed skip dirs at the repo root must match (regression: lstrip ate the dot)
    assert cli._is_skipped(".git/config", (".git",)) is True
    assert cli._is_skipped(".terraform/main.tf", (".terraform",)) is True
    assert cli._is_skipped("./src/app.py", (".git",)) is False


def test_findings_in_skipped_dirs_are_filtered(monkeypatch, tmp_path):
    crit = Finding(
        rule_id="R", title="t", severity=Sev.CRITICAL, domain=Domain.IAC,
        tool="fake", file="node_modules/pkg/x.tf", line=1,
    )
    code, _ = _run(monkeypatch, tmp_path, [crit])
    assert code == cli.EXIT_OK  # the only finding is under a default skip dir


def test_domain_assessed_only_via_skipped_paths_is_dropped_from_grade(monkeypatch, tmp_path):
    # IaC's only finding is under a skip dir: IaC must not be scored 100, it should
    # drop out of the grade entirely (not a misleading perfect worst-domain).
    crit = Finding(
        rule_id="R", title="t", severity=Sev.CRITICAL, domain=Domain.IAC,
        tool="fake", file="node_modules/pkg/x.tf", line=1,
    )
    code, out = _run(monkeypatch, tmp_path, [crit], extra=["--format", "json"])
    payload = json.loads((out / "report.json").read_text(encoding="utf-8"))
    assert code == cli.EXIT_OK
    assert all(d["domain"] != "iac" for d in payload["score"]["domains"])


def test_output_dir_pointing_at_a_file_returns_env_error(monkeypatch, tmp_path):
    existing = tmp_path / "afile"
    existing.write_text("x", encoding="utf-8")
    monkeypatch.setattr(cli, "ALL_RUNNERS", (_make_runner([_finding(Sev.LOW)]),))
    assert cli.main([str(tmp_path), "--output-dir", str(existing)]) == cli.EXIT_ENV_ERROR
