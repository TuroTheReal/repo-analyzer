"""Parsing tests for the M2 runners (gitleaks, grype, hadolint, checkov).

Each runner exposes a pure ``_parse`` so we test the JSON-to-Finding mapping on
synthetic output slices without invoking the real binary.
"""

from pathlib import Path

from repo_analyzer.core.finding import Domain, Severity
from repo_analyzer.runners.checkov import CheckovRunner
from repo_analyzer.runners.gitleaks import GitleaksRunner
from repo_analyzer.runners.grype import GrypeRunner
from repo_analyzer.runners.hadolint import HadolintRunner


def test_gitleaks_maps_secrets_without_leaking_the_value():
    # The Secret value below is an intentionally non-matching placeholder so
    # gitleaks does not flag this test file when repo-analyzer scans itself.
    secret_value = "DUMMY_PLACEHOLDER_VALUE_0000"
    data = [{"RuleID": "aws-access-token", "Description": "AWS token", "File": "main.tf",
             "StartLine": 3, "Secret": secret_value}]
    findings = GitleaksRunner()._parse(data)
    assert len(findings) == 1
    f = findings[0]
    assert f.domain is Domain.SECRETS
    assert f.severity is Severity.HIGH
    assert f.rule_id == "aws-access-token"
    assert f.file == "main.tf" and f.line == 3
    assert secret_value not in (f.message + (f.remediation or ""))


def test_gitleaks_never_leaks_secret_or_match():
    data = [{"RuleID": "x", "Description": "d", "File": "f", "StartLine": 1,
             "Secret": "SUPERSECRETVALUE", "Match": "key = SUPERSECRETVALUE"}]
    f = GitleaksRunner()._parse(data)[0]
    blob = " ".join(str(v) for v in (f.title, f.message, f.remediation, f.rule_id))
    assert "SUPERSECRETVALUE" not in blob


def test_gitleaks_relativizes_absolute_paths(tmp_path):
    # gitleaks reports absolute paths; they must become root-relative so
    # skip_dirs (e.g. tests/fixtures) can match them.
    abs_path = str(tmp_path / "sub" / "app.env")
    data = [{"RuleID": "x", "Description": "d", "File": abs_path, "StartLine": 1, "Secret": "z"}]
    f = GitleaksRunner()._parse(data, tmp_path)[0]
    assert f.file == "sub/app.env"


def test_grype_maps_cve_and_fix_version():
    data = {
        "matches": [
            {
                "vulnerability": {
                    "id": "CVE-2021-1234", "severity": "High",
                    "dataSource": "https://nvd.nist.gov/vuln/detail/CVE-2021-1234",
                    "fix": {"versions": ["1.2.4"], "state": "fixed"},
                },
                "artifact": {"name": "requests", "version": "1.2.3", "locations": []},
            }
        ]
    }
    f = GrypeRunner()._parse(data, Path("/tmp"))[0]
    assert f.domain is Domain.DEPENDENCIES
    assert f.rule_id == "CVE-2021-1234"
    assert f.severity is Severity.HIGH
    assert f.resource == "requests@1.2.3"
    assert f.remediation == "Upgrade requests to 1.2.4"
    assert f.references[0].startswith("https://")


def test_hadolint_maps_levels_to_severities():
    data = [
        {"line": 1, "code": "DL3006", "message": "Always tag the version", "level": "warning", "file": "Dockerfile"},
        {"line": 2, "code": "DL3002", "message": "Last USER should not be root", "level": "error", "file": "Dockerfile"},
    ]
    findings = HadolintRunner()._parse(data, "Dockerfile")
    sev = {f.rule_id: f.severity for f in findings}
    assert sev["DL3006"] is Severity.MEDIUM  # warning
    assert sev["DL3002"] is Severity.HIGH  # error
    assert all(f.domain is Domain.CONTAINER for f in findings)
    assert findings[0].references[0].startswith("https://github.com/hadolint")


def test_checkov_parses_failed_checks_from_list_or_object():
    obj = {
        "check_type": "terraform",
        "results": {
            "failed_checks": [
                {
                    "check_id": "CKV_AWS_20",
                    "check_name": "S3 bucket should not be public",
                    "file_path": "/main.tf",
                    "file_line_range": [1, 4],
                    "resource": "aws_s3_bucket.data",
                    "severity": None,
                    "guideline": "https://docs.bridgecrew.io/docs/s3",
                }
            ],
            "passed_checks": [],
        },
    }
    # checkov emits a list when several frameworks are scanned.
    findings = CheckovRunner()._parse([obj])
    assert len(findings) == 1
    f = findings[0]
    assert f.domain is Domain.IAC
    assert f.rule_id == "CKV_AWS_20"
    assert f.file == "main.tf"  # leading slash stripped
    assert f.line == 1
    assert f.resource == "aws_s3_bucket.data"
    assert f.severity is Severity.MEDIUM  # null severity -> default
    # Same input as a single object (one framework) parses identically.
    assert len(CheckovRunner()._parse(obj)) == 1


def test_checkov_handles_empty():
    assert CheckovRunner()._parse([]) == []
    assert CheckovRunner()._parse({"results": {"failed_checks": []}}) == []


def test_checkov_routes_kubernetes_to_container():
    k8s = {
        "check_type": "kubernetes",
        "results": {"failed_checks": [
            {"check_id": "CKV_K8S_1", "check_name": "no privileged containers",
             "file_path": "/deploy.yaml", "file_line_range": [1, 5], "resource": "Deployment.app"}
        ]},
    }
    f = CheckovRunner()._parse(k8s)[0]
    assert f.domain is Domain.CONTAINER  # kubernetes -> Container, not IaC
