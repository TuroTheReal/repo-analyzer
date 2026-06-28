"""Merge and deduplicate findings coming from several scanners.

Deduplication is by exact :attr:`Finding.dedup_key` (rule + file + line +
resource), keeping the highest-severity variant. This collapses a finding that a
single tool reports more than once. It does NOT merge the *same* issue flagged by
*different* tools: each tool uses its own rule IDs (Trivy ``AVD-``, Checkov
``CKV_``), so their keys never collide. True cross-tool semantic dedup would need
a rule-to-rule mapping, which this project deliberately does not attempt.
"""

from __future__ import annotations

from dataclasses import dataclass

from .finding import Finding


@dataclass(frozen=True)
class MergeResult:
    """Outcome of a merge: the deduplicated findings plus how many were dropped."""

    findings: list[Finding]
    duplicates_removed: int


def merge(*finding_lists: list[Finding]) -> MergeResult:
    """Deduplicate findings across runners.

    Args:
        *finding_lists: One list of findings per runner.

    Returns:
        A :class:`MergeResult` with findings sorted by descending severity then
        domain, file and line for stable, readable reports.
    """
    seen: dict[str, Finding] = {}
    total = 0
    for findings in finding_lists:
        for finding in findings:
            total += 1
            # Without any location (file/line/resource) two distinct issues
            # share the same dedup_key, so deduping would silently drop one and
            # inflate the grade. Keep every location-less finding instead: a
            # security gate must over-count rather than under-count.
            if not (finding.file or finding.line or finding.resource):
                seen[f"{finding.dedup_key}#{len(seen)}"] = finding
                continue
            existing = seen.get(finding.dedup_key)
            if existing is None or finding.severity.rank > existing.severity.rank:
                seen[finding.dedup_key] = finding

    ordered = sorted(
        seen.values(),
        key=lambda f: (-f.severity.rank, f.domain.value, f.file or "", f.line or 0),
    )
    return MergeResult(findings=ordered, duplicates_removed=total - len(ordered))
