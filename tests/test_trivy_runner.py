"""Tests for the Trivy runner: deterministic parsing + an optional live scan."""

import shutil
from pathlib import Path

import pytest

from repo_analyzer.core.finding import Domain, Severity
from repo_analyzer.runners.trivy import TrivyConfigRunner

FIXTURE = Path(__file__).parent / "fixtures" / "vulnerable-iac"

# Slice mirroring real `trivy config --format json` output: the ID is the short
# form (e.g. "AWS-0107") and there is no top-level AVDID key.
SAMPLE = {
    "Results": [
        {
            "Target": "main.tf",
            "Class": "config",
            "Type": "terraform",
            "Misconfigurations": [
                {
                    "ID": "AWS-0107",
                    "Title": "An ingress security group rule allows traffic from /0",
                    "Message": "Security group rule allows ingress from public internet.",
                    "Resolution": "Set a more restrictive cidr range",
                    "Severity": "CRITICAL",
                    "PrimaryURL": "https://avd.aquasec.com/misconfig/avd-aws-0107",
                    "References": ["https://avd.aquasec.com/misconfig/avd-aws-0107"],
                    "Status": "FAIL",
                    "CauseMetadata": {"Resource": "aws_security_group.open", "StartLine": 18},
                },
                {
                    "ID": "AWS-0089",
                    "Title": "S3 Bucket does not have logging enabled.",
                    "Severity": "LOW",
                    "Status": "PASS",
                    "CauseMetadata": {},
                },
            ],
        }
    ]
}


def test_parse_keeps_failing_checks_only_and_maps_fields():
    findings = TrivyConfigRunner()._parse(SAMPLE)
    assert len(findings) == 1  # the PASS one is dropped
    finding = findings[0]
    assert finding.rule_id == "AWS-0107"  # ID, since real Trivy has no AVDID
    assert finding.severity is Severity.CRITICAL
    assert finding.domain is Domain.IAC
    assert finding.file == "main.tf"
    assert finding.line == 18
    assert finding.resource == "aws_security_group.open"
    assert finding.remediation == "Set a more restrictive cidr range"
    assert finding.references[0].startswith("https://")


def test_parse_prefers_avdid_when_present_and_falls_back_to_primary_url():
    sample = {
        "Results": [
            {
                "Target": "k8s.yaml",
                "Type": "kubernetes",
                "Misconfigurations": [
                    {
                        "ID": "KSV001",
                        "AVDID": "AVD-KSV-0001",
                        "Title": "Privileged container",
                        "Severity": "HIGH",
                        "PrimaryURL": "https://avd.aquasec.com/misconfig/ksv001",
                        # No References list -> falls back to PrimaryURL.
                        "Status": "FAIL",
                        "CauseMetadata": {},
                    }
                ],
            }
        ]
    }
    finding = TrivyConfigRunner()._parse(sample)[0]
    assert finding.rule_id == "AVD-KSV-0001"  # AVDID wins over ID
    assert finding.domain is Domain.CONTAINER  # kubernetes routes to Container, not IaC
    assert finding.file == "k8s.yaml"
    assert finding.line is None  # no StartLine
    assert finding.resource is None  # no Resource
    assert finding.references == ("https://avd.aquasec.com/misconfig/ksv001",)


def test_parse_handles_empty_and_status_less_input():
    assert TrivyConfigRunner()._parse({}) == []
    assert TrivyConfigRunner()._parse({"Results": []}) == []
    # A misconfiguration without a Status defaults to FAIL (kept).
    status_less = {"Results": [{"Target": "f.tf", "Misconfigurations": [{"ID": "X", "Severity": "LOW"}]}]}
    assert len(TrivyConfigRunner()._parse(status_less)) == 1


@pytest.mark.skipif(shutil.which("trivy") is None, reason="trivy not installed")
def test_live_scan_flags_the_vulnerable_fixture():
    result = TrivyConfigRunner().run(FIXTURE)
    assert Domain.IAC in result.applicable_domains, "fixture has Terraform, so IaC must be assessed"
    assert result.findings, "expected misconfigurations in the vulnerable fixture"
    assert any(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in result.findings)
