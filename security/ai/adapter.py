"""Adapt a deterministic investigation into the minimized AI contract."""

from security.ai.contract import AIInput
from security.ai.privacy import build_ai_input
from security.models.schemas import InvestigationResult


def adapt_investigation(result: InvestigationResult) -> AIInput:
    """Return only the privacy-filtered, structured AI context."""
    return build_ai_input(result)
