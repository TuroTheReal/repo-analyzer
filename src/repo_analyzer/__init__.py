"""repo-analyzer: a thin DevSecOps gate.

It orchestrates best-in-class scanners (Trivy, Checkov, gitleaks, grype,
hadolint; zizmor and actionlint planned), normalizes their output into a single
finding model, scores the result into a letter grade, and emits SARIF / Markdown
/ HTML / JSON. The process exit code turns the report into a CI gate.

The detection logic lives in the underlying tools, which maintain their own
rule and vulnerability databases. This package only owns the orchestration,
scoring and reporting layers.
"""

__version__ = "0.1.0"
