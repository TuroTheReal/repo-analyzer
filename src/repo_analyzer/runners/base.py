"""Runner abstraction shared by every scanner wrapper.

A runner wraps exactly one external tool. It declares which security
:class:`Domain` s it covers, says whether the tool is installed, and turns the
tool's native output into unified :class:`Finding` objects.

The :func:`run_command` helper centralizes safe subprocess execution: argv form
only (never ``shell=True``), a timeout, and an explicit error when the tool
exits non-zero, so a real failure can never be silently read as "no findings".
"""

from __future__ import annotations

import shutil
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path

from ..core.finding import Domain, Finding


class RunnerError(RuntimeError):
    """Raised when a tool fails in a way that invalidates its results."""


# Routes an IaC scanner's file type to a domain so Trivy/Checkov send
# Kubernetes/Dockerfile/Helm findings to Container and the rest to IaC.
_IAC_TYPE_DOMAIN: dict[str, Domain] = {
    "terraform": Domain.IAC,
    "terraformplan": Domain.IAC,
    "terraform_plan": Domain.IAC,
    "cloudformation": Domain.IAC,
    "azure-arm": Domain.IAC,
    "arm": Domain.IAC,
    "kubernetes": Domain.CONTAINER,
    "dockerfile": Domain.CONTAINER,
    "docker": Domain.CONTAINER,
    "helm": Domain.CONTAINER,
}


def domain_for_iac_type(file_type: str | None) -> Domain:
    """Route an IaC scanner file type to a domain (defaults to IaC)."""
    return _IAC_TYPE_DOMAIN.get((file_type or "").strip().lower(), Domain.IAC)


def workflow_files(root: Path) -> list[Path]:
    """GitHub Actions workflow files under ``.github/workflows`` (pipeline domain)."""
    workflows = root / ".github" / "workflows"
    if not workflows.is_dir():
        return []
    return sorted(p for p in workflows.iterdir() if p.is_file() and p.suffix in (".yml", ".yaml"))


def relative_to_root(path: object, root: "Path | None") -> str | None:
    """Make a tool-reported path relative to the scan root when possible.

    Accepts str / Path / None; falls back to a leading-slash-stripped string
    when the path is outside root or the root is unknown.
    """
    if not path:
        return None
    if root is None:
        return str(path).lstrip("/")
    try:
        return str(Path(path).resolve().relative_to(root.resolve()))
    except ValueError:
        return str(path).lstrip("/")


@dataclass(frozen=True)
class RunnerResult:
    """A runner's output.

    Attributes:
        findings: The normalized findings.
        applicable_domains: The domains the runner actually assessed, i.e. for
            which relevant files were present (e.g. IaC files, a Dockerfile, a
            dependency manifest). A clean-but-assessed domain scores 100; a
            domain with no relevant files is excluded from the grade and flagged
            as "not assessed" rather than shown as a misleading perfect score.
            A single runner can assess several domains (Trivy/Checkov route
            Kubernetes/Dockerfile/Helm to Container and Terraform/CFN to IaC).
    """

    findings: list[Finding]
    applicable_domains: frozenset[Domain]
    #: The tool's native output, kept so the report can link it for digging.
    #: None when it must not be exposed (gitleaks raw contains the secret value).
    raw: str | None = None


class Runner(ABC):
    """Base class for all scanner runners."""

    #: Display name, also used as the ``tool`` field on findings.
    name: str
    #: Binary that must be on PATH for this runner to work.
    binary: str

    def is_available(self) -> bool:
        """Whether the underlying tool is installed and on PATH."""
        return shutil.which(self.binary) is not None

    @abstractmethod
    def run(self, root: Path) -> RunnerResult:
        """Scan ``root``. Raises :class:`RunnerError` on failure."""
        raise NotImplementedError


def run_command(cmd: list[str], cwd: Path, timeout: int, ok_codes: tuple[int, ...] = (0,)) -> str:
    """Run ``cmd`` (argv form) in ``cwd`` and return its stdout.

    Args:
        cmd: Command and arguments, never passed through a shell.
        cwd: Working directory.
        timeout: Hard timeout in seconds.
        ok_codes: Exit codes treated as success. Most tools use a no-fail flag so
            only 0 is success; a few (e.g. actionlint) use a non-zero code to mean
            "issues found", which is not a tool failure.

    Returns:
        Captured stdout.

    Raises:
        RunnerError: If the command times out or exits with a code not in ``ok_codes``.
    """
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(cwd),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise RunnerError(f"{cmd[0]} timed out after {timeout}s") from exc
    except FileNotFoundError as exc:
        raise RunnerError(f"{cmd[0]} not found on PATH") from exc

    if proc.returncode not in ok_codes:
        stderr = (proc.stderr or "").strip()
        raise RunnerError(
            f"{cmd[0]} exited with code {proc.returncode}: {stderr[:500] or '<no stderr>'}"
        )
    return proc.stdout
