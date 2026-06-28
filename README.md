# repo-analyzer

A thin **DevSecOps gate**. It orchestrates best-in-class security scanners,
merges their output into one scored report, and turns the result into a CI gate
via its exit code.

> **Status: rebuild in progress.** The tool was rewritten from a custom scanner
> into a thin orchestrator. Milestone 1 (below) is functional; the rest is on
> the roadmap. This README only documents what actually works today.

## Philosophy

Detection lives in the underlying tools (Trivy, gitleaks, grype, ...), which
maintain their own rule and vulnerability databases. This project owns only the
layers that add value and barely change:

- **orchestration** of the scanners,
- **normalization** into a single finding model + dedup,
- **scoring** into a letter grade (only over the domains actually scanned),
- **reporting** to SARIF / Markdown / HTML / JSON,
- the **gate** (process exit code).

## What works today (M1 + M2)

Five scanners, each optional (skipped if its binary is absent), normalized into
one model and one grade:

| Domain | Tool | Covers |
|--------|------|--------|
| IaC | **Trivy** (`trivy config`) | Terraform, CloudFormation, K8s, Helm: AWS/GCP/Azure |
| IaC | **Checkov** | second, independent IaC policy engine |
| Dependencies | **grype** | known CVEs in package manifests |
| Secrets | **gitleaks** | hardcoded credentials (value never stored) |
| Container | **hadolint** | Dockerfile best practices |

- Unified, deduplicated findings with a 0-100 score and A+..F grade (computed
  only over the domains that were actually scanned).
- Four report formats:
  - **SARIF 2.1.0**: ingested by GitHub code scanning (inline PR annotations).
  - **Markdown**: for PR comments and terminal reading.
  - **HTML**: a self-contained dark dashboard (autoescaped, URL-scheme checked).
  - **JSON**: canonical machine-readable output.
- A configurable **gate**: the process exits non-zero when a finding reaches a
  fail-on severity.
- `scan.skip_dirs` to exclude paths (vendored deps, fixtures) from the grade.

## Requirements

- Python 3.10+
- At least one scanner on `PATH`. Install all via Homebrew:
  `brew install trivy checkov grype gitleaks hadolint`.

## Install

```bash
make install        # creates .venv and installs the package + dev deps
```

## Usage

```bash
repo-analyzer <path> \
  [--fail-on critical,high] \
  [--format sarif,markdown,html,json] \
  [--output-dir DIR] \
  [--no-gate]
```

Exit codes: `0` gate passed, `1` gate failed, `2` usage/environment error.

```bash
make self           # scan this repo (dogfood)
make test           # run the test suite
```

## Use it in another repo (GitHub Action)

Add one step to any workflow:

```yaml
- uses: actions/checkout@v4
- uses: TuroTheReal/repo-analyzer@v1
  with:
    fail-on: critical,high   # optional
```

Inputs (all optional):

| Input | Default | Description |
|---|---|---|
| `target` | `.` | path to scan |
| `fail-on` | config, else `critical,high` | severities that fail the gate |
| `format` | config | report formats (sarif,markdown,html,json) |
| `output-dir` | `repo-analyzer-report` | where reports are written |
| `config` | `<target>/.repo-analyzer.yml` | config file |
| `no-gate` | `false` | scan + report without failing CI |

Pin to `@v1` for non-breaking updates, or to a full commit SHA for maximum supply-chain safety.

## Configuration

Optional `.repo-analyzer.yml` at the scanned repo root:

```yaml
gate:
  fail_on: [critical, high]
output:
  formats: [sarif, markdown, html, json]
  dir: repo-analyzer-report
```

## Roadmap

- [x] **M1**: Trivy IaC + core model + scoring + reporters + gate
- [x] **M2**: Checkov, gitleaks, grype, hadolint + `skip_dirs` + dark HTML dashboard (SVG charts, severity filter)
- [ ] **M3**: packaged GitHub Action + self-scan (dogfood)
- [x] **M4**: pipeline audit (zizmor + actionlint) — Pipeline domain, self-scan hardens its own workflow (SHA-pinned actions)
- [ ] **M5**: GitHub Pages demo dashboard
- [ ] later: OpenSSF Scorecard (supply-chain posture)

## Known limitations

- **Checkov severities**: without a platform key (the common OSS setup) Checkov emits
  no severity, so its findings default to Medium. Rely on Trivy for authoritative IaC
  severity; Checkov adds breadth, not severity precision.
- **A missing scanner is a silent gap**: a domain is assessed only if its tool is
  installed and ran. If a relevant tool is absent, that domain is reported as
  "not assessed" rather than flagged as unscanned risk. Install all scanners for full coverage.
- **Secrets are always High**: every gitleaks match is treated as High (gate-failing),
  with no per-rule confidence. Tune via `gate.fail_on`, or scope example keys/fixtures
  with `scan.skip_dirs`.

## License

MIT: see [LICENSE](LICENSE).
