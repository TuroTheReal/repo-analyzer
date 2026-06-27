"""Scanner runners: each wraps one external tool and emits unified findings."""

from .base import Runner, RunnerError, RunnerResult
from .checkov import CheckovRunner
from .gitleaks import GitleaksRunner
from .grype import GrypeRunner
from .hadolint import HadolintRunner
from .trivy import TrivyConfigRunner

# Registry of runners the CLI will try, in order. Each is skipped when its
# underlying tool is not installed (see Runner.is_available).
ALL_RUNNERS: tuple[type[Runner], ...] = (
    TrivyConfigRunner,
    CheckovRunner,
    GitleaksRunner,
    GrypeRunner,
    HadolintRunner,
)

__all__ = [
    "Runner",
    "RunnerError",
    "RunnerResult",
    "TrivyConfigRunner",
    "CheckovRunner",
    "GitleaksRunner",
    "GrypeRunner",
    "HadolintRunner",
    "ALL_RUNNERS",
]
