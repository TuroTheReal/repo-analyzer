"""NIST SSDF (SP 800-218) coverage mapping — the seed of "audit mode".

Maps repo-analyzer's security domains to the SSDF practices they speak to, so a
scan can report per-practice coverage ("PW.4 covered by dependencies; PW.7 SAST
is a gap") instead of only a hygiene grade. This is an INDICATIVE mapping meant
to guide a gap analysis, NOT an official SSDF attestation.
"""

from __future__ import annotations

from dataclasses import dataclass

from .finding import Domain


@dataclass(frozen=True)
class Practice:
    """One SSDF practice repo-analyzer can speak to."""

    id: str
    title: str


# Subset of SP 800-218 practices repo-analyzer's domains provide evidence for.
_PRACTICES: tuple[Practice, ...] = (
    Practice("PW.4", "Reuse well-secured components and track their vulnerabilities"),
    Practice("PW.6", "Configure the build / CI process to improve security"),
    Practice("PW.7", "Review and analyze human-readable code for vulnerabilities (SAST)"),
    Practice("PW.9", "Configure software with secure default settings"),
    Practice("PS.1", "Protect code from unauthorized access and tampering"),
    Practice("PS.2", "Provide a mechanism to verify software release integrity"),
    Practice("RV.1", "Identify and confirm vulnerabilities on an ongoing basis"),
)

# Which assessed domain contributes evidence toward each practice.
_DOMAIN_PRACTICES: dict[Domain, tuple[str, ...]] = {
    Domain.DEPENDENCIES: ("PW.4", "RV.1"),
    Domain.CODE: ("PW.7",),
    Domain.IAC: ("PW.9",),
    Domain.CONTAINER: ("PW.9",),
    Domain.SECRETS: ("PS.1",),
    Domain.PIPELINE: ("PW.6",),
    Domain.SUPPLY_CHAIN: ("PS.1", "PS.2", "RV.1"),
}


@dataclass(frozen=True)
class PracticeCoverage:
    """A practice and the assessed domains that provide evidence for it."""

    practice: Practice
    covered_by: tuple[Domain, ...]

    @property
    def covered(self) -> bool:
        return bool(self.covered_by)


def coverage(assessed: set[Domain]) -> list[PracticeCoverage]:
    """Per-practice coverage given the domains that were actually assessed."""
    by_practice: dict[str, list[Domain]] = {p.id: [] for p in _PRACTICES}
    for domain in assessed:
        for practice_id in _DOMAIN_PRACTICES.get(domain, ()):
            by_practice[practice_id].append(domain)
    return [
        PracticeCoverage(p, tuple(sorted(by_practice[p.id], key=lambda d: d.value)))
        for p in _PRACTICES
    ]


def to_markdown(rows: list[PracticeCoverage], repo_name: str) -> str:
    """Render the coverage as a Markdown gap-analysis report."""
    covered = sum(1 for row in rows if row.covered)
    lines = [
        f"# SSDF coverage — {repo_name}",
        "",
        f"**{covered}/{len(rows)} practices covered.** Indicative mapping to NIST SP 800-218 "
        "to guide a gap analysis — not an official attestation.",
        "",
        "| Practice | What it asks | Covered by | Status |",
        "|----------|--------------|------------|--------|",
    ]
    for row in rows:
        by = ", ".join(d.value for d in row.covered_by) if row.covered_by else "—"
        status = "✅ covered" if row.covered else "❌ gap"
        lines.append(f"| {row.practice.id} | {row.practice.title} | {by} | {status} |")
    lines.append("")
    return "\n".join(lines)
