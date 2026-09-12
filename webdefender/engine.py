"""Canonical Web Defender engine composition."""
from .analyzer.base import AnalyzerBase
from .analyzer.orchestrator import ScanOrchestratorMixin
from .analyzer.acquisition import AcquisitionSensorsMixin
from .analyzer.context_sensors import ContextSensorsMixin
from .guards.runtime import EvidenceGuardsMixin
from .fusion.family_experts import ThreatFamilyExpertsMixin
from .fusion.decision_pipeline import DecisionEvidenceMixin
from .analyzer.operations import OperationalLearningMixin
from .analyzer.residual_services import ResidualServicesMixin
from .application import app, APP_NAME, APP_VERSION

class SecurityAnalyzer(
    ScanOrchestratorMixin,
    AcquisitionSensorsMixin,
    ContextSensorsMixin,
    EvidenceGuardsMixin,
    ThreatFamilyExpertsMixin,
    DecisionEvidenceMixin,
    OperationalLearningMixin,
    ResidualServicesMixin,
    AnalyzerBase,
):
    """Canonical analyzer. Final decision remains owned by fusion policy."""

WebDefenderAnalyzer=SecurityAnalyzer

def analyze_target(url: str, feed_off: bool=True):
    return WebDefenderAnalyzer(url, feed_off=feed_off).analyze_url()

# Register presentation/API routes only after engine composition exists.
from .routes import web as _web_routes  # noqa: E402,F401
