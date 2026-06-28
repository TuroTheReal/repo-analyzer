"""Command-line entry point and CI gate.

Usage:
    repo-analyzer <path> [--format sarif,markdown,html,json]
                         [--fail-on critical,high] [--output-dir DIR]
                         [--no-gate] [--quiet]

Exit codes:
    0  gate passed (or --no-gate)
    1  gate failed (a finding at or above a fail-on severity)
    2  usage / environment error (bad path, no scanner installed)
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

from rich.console import Console

from .config import Config, ConfigError
from .core import merger, scorer
from .core.finding import Domain, Finding, Severity
from .report import Report
from .reporters import REPORTERS
from .runners import ALL_RUNNERS
from .runners.base import RunnerError

console = Console()

EXIT_OK = 0
EXIT_GATE_FAILED = 1
EXIT_ENV_ERROR = 2


def _parse_severities(value: str) -> tuple[frozenset[Severity], list[str]]:
    """Parse a comma-separated severity list; return ``(valid, unknown_tokens)``.

    Unknown tokens are reported, never coerced to a default: a typo in the gate
    threshold must surface, not silently weaken or alter the gate.
    """
    valid: set[Severity] = set()
    unknown: list[str] = []
    for part in value.split(","):
        token = part.strip()
        if not token:
            continue
        severity = Severity.try_parse(token)
        if severity is None:
            unknown.append(token)
        else:
            valid.add(severity)
    return frozenset(valid), unknown


def _parse_formats(value: str) -> tuple[tuple[str, ...], list[str]]:
    """Parse a comma-separated format list; return ``(valid, unknown_tokens)``."""
    valid: list[str] = []
    unknown: list[str] = []
    for part in value.split(","):
        token = part.strip().lower()
        if not token:
            continue
        (valid if token in REPORTERS else unknown).append(token)
    return tuple(valid), unknown


def _is_skipped(file: str | None, skip_dirs: tuple[str, ...]) -> bool:
    """Whether a finding's path falls under a skipped directory.

    Both forms match anywhere in the path: a single segment (e.g.
    ``node_modules``) matches any path component; a multi-segment entry (e.g.
    ``tests/fixtures``) matches any contiguous run of components. Absolute paths
    and a leading ``./`` are normalized first.
    """
    if not file:
        return False
    norm = file.replace("\\", "/")
    # Strip a literal "./" prefix or a leading "/", NOT a set of chars: lstrip("./")
    # would also eat the dot of ".git"/".terraform" and break dot-dir skipping.
    norm = norm[2:] if norm.startswith("./") else norm.lstrip("/")
    segments = norm.split("/")
    padded = "/" + norm + "/"
    for raw in skip_dirs:
        entry = raw.strip("/").replace("\\", "/")
        if not entry:
            continue
        if "/" in entry:
            if ("/" + entry + "/") in padded:
                return True
        elif entry in segments:
            return True
    return False


def _run_scanners(target: Path) -> tuple[list[Finding], set[Domain], list[str], dict[str, str]]:
    """Run every available runner.

    Returns the findings, the set of domains actually *applicable* (relevant
    files present), the names of the tools that ran, and a {tool: raw_output}
    map (only tools that expose a safe raw report; gitleaks is omitted).
    """
    findings: list[Finding] = []
    applicable: set[Domain] = set()
    tools: list[str] = []
    raws: dict[str, str] = {}

    for runner_cls in ALL_RUNNERS:
        runner = runner_cls()
        if not runner.is_available():
            console.print(f"[dim]skip {runner.name}: binary '{runner.binary}' not on PATH[/dim]")
            continue
        console.print(f"[cyan]running {runner.name}...[/cyan]")
        try:
            result = runner.run(target)
        except RunnerError as exc:
            console.print(f"[red]{runner.name} failed:[/red] {exc}")
            continue
        findings.extend(result.findings)
        tools.append(runner.name)
        applicable.update(result.applicable_domains)
        if result.raw is not None:
            raws[runner.name] = result.raw

    return findings, applicable, tools, raws


def _print_summary(report: Report) -> None:
    """Print a short human summary to the console."""
    score = report.score
    color = "green" if score.passed else "red"
    gate = "PASSED" if score.passed else "FAILED"
    console.print(
        f"\n[bold]Grade {score.grade} ({score.total}/100)[/bold] · "
        f"[bold {color}]gate {gate}[/bold {color}]"
    )
    parts = [
        f"{score.counts.get(sev, 0)} {sev.value}"
        for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW)
    ]
    console.print(f"[dim]{' · '.join(parts)} · {len(report.findings)} total[/dim]")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="repo-analyzer", description="DevSecOps gate.")
    parser.add_argument("target", help="Path to the repository or directory to scan.")
    parser.add_argument("--format", dest="formats", help="Comma-separated output formats.")
    parser.add_argument("--fail-on", dest="fail_on", help="Comma-separated severities that fail the gate.")
    parser.add_argument("--output-dir", dest="output_dir", help="Directory for the generated reports.")
    parser.add_argument("--config", dest="config", help="Path to a .repo-analyzer.yml (defaults to <target>/.repo-analyzer.yml).")
    parser.add_argument("--no-gate", action="store_true", help="Always exit 0, regardless of findings.")
    parser.add_argument("--quiet", action="store_true", help="Suppress per-runner progress output.")
    return parser


def main(argv: list[str] | None = None) -> int:
    """Entry point. Returns the process exit code."""
    args = _build_parser().parse_args(argv)
    if args.quiet:
        console.quiet = True

    target = Path(args.target).expanduser().resolve()
    if not target.is_dir():
        console.print(f"[red]error:[/red] not a directory: {target}")
        return EXIT_ENV_ERROR

    try:
        if args.config:
            config = Config.from_file(Path(args.config).expanduser().resolve(), required=True)
        else:
            config = Config.load(target)
    except ConfigError as exc:
        console.print(f"[red]config error:[/red] {exc}")
        return EXIT_ENV_ERROR

    if args.fail_on:
        fail_on, unknown = _parse_severities(args.fail_on)
        if unknown:
            console.print(
                f"[red]error:[/red] unknown severity: {', '.join(unknown)} "
                "(valid: critical, high, medium, low, info)"
            )
            return EXIT_ENV_ERROR
        if not fail_on:
            console.print("[red]error:[/red] --fail-on is empty")
            return EXIT_ENV_ERROR
    else:
        fail_on = config.fail_on

    if args.formats:
        formats, unknown_formats = _parse_formats(args.formats)
        if unknown_formats:
            console.print(f"[yellow]warning:[/yellow] ignoring unknown format(s): {', '.join(unknown_formats)}")
        if not formats:
            console.print(f"[red]error:[/red] no valid format in --format (valid: {', '.join(REPORTERS)})")
            return EXIT_ENV_ERROR
    else:
        formats = config.formats

    output_dir = Path(args.output_dir or config.output_dir).expanduser().resolve()

    findings, applicable, tools, raws = _run_scanners(target)
    if not tools:
        console.print(
            "[red]error:[/red] no scanner available. Install at least one of: "
            "trivy, checkov, gitleaks, grype, hadolint"
        )
        return EXIT_ENV_ERROR

    # skip_dirs excludes configured paths (vendored deps, fixtures) from BOTH the
    # findings and the grade. A domain a runner actually assessed stays assessed on
    # the remaining files (clean = 100 if all its findings were skipped): we trust
    # the runner's applicability instead of dropping a genuinely-scanned domain to
    # "not assessed", which would hide that, say, secrets were scanned and clean.
    findings = [f for f in findings if not _is_skipped(f.file, config.skip_dirs)]
    merged = merger.merge(findings)
    result = scorer.score(merged.findings, applicable, fail_on)

    report = Report(
        repo_name=target.name,
        target=str(target),
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        findings=merged.findings,
        score=result,
        tools=tools,
        duplicates_removed=merged.duplicates_removed,
        raw_tools=sorted(raws),
    )

    try:
        output_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        console.print(f"[red]error:[/red] cannot create output dir {output_dir}: {exc}")
        return EXIT_ENV_ERROR
    for fmt in formats:
        render, filename = REPORTERS[fmt]
        (output_dir / filename).write_text(render(report), encoding="utf-8")
    if raws:
        raw_dir = output_dir / "raw"
        raw_dir.mkdir(exist_ok=True)
        for tool, content in raws.items():
            (raw_dir / f"{tool}.json").write_text(content, encoding="utf-8")
    console.print(f"[dim]reports written to {output_dir}[/dim]")

    _print_summary(report)

    if args.no_gate:
        return EXIT_OK
    return EXIT_OK if result.passed else EXIT_GATE_FAILED


if __name__ == "__main__":
    sys.exit(main())
