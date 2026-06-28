"""Scanner runners: each wraps one external tool and emits unified findings."""

from .actionlint import ActionlintRunner
from .base import Runner, RunnerError, RunnerResult
from .checkov import CheckovRunner
from .gitleaks import GitleaksRunner
from .grype import GrypeRunner
from .hadolint import HadolintRunner
from .scorecard import ScorecardRunner
from .trivy import TrivyConfigRunner
from .zizmor import ZizmorRunner

# Registry of runners the CLI will try, in order. Each is skipped when its
# underlying tool is not installed (see Runner.is_available).
ALL_RUNNERS: tuple[type[Runner], ...] = (
    TrivyConfigRunner,
    CheckovRunner,
    GitleaksRunner,
    GrypeRunner,
    HadolintRunner,
    ZizmorRunner,
    ActionlintRunner,
    ScorecardRunner,
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
    "ZizmorRunner",
    "ActionlintRunner",
    "ScorecardRunner",
    "ALL_RUNNERS",
]
