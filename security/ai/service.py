"""Synchronous orchestration for privacy-safe AI-assisted investigation."""

from __future__ import annotations

from copy import deepcopy
from typing import Literal, TypedDict

from security.ai.adapter import adapt_investigation
from security.ai.contract import AIAnalysis, AIInput
from security.ai.provider import AIProvider, AIProviderError
from security.ai.validation import validate_ai_input, validate_ai_output
from security.models.schemas import InvestigationResult


class AIServiceResult(TypedDict):
    """Validated analysis plus display metadata, separate from security data."""

    provider_id: str
    mode: Literal["MOCK/DEMO", "PROVIDER"]
    analysis: AIAnalysis


def analyze_investigation(
    result: InvestigationResult,
    provider: AIProvider,
) -> AIServiceResult:
    """Build, validate, analyze, and validate a fresh context in one call.

    The source result and canonical context remain in scope for the complete
    synchronous operation, preserving Phase 1's process-local pseudonym state.
    Providers receive independent copies and cannot mutate the source context.
    """
    canonical_context: AIInput = adapt_investigation(result)
    validate_ai_input(canonical_context, source_result=result)
    provider_id = getattr(provider, "provider_id", None)
    if not isinstance(provider_id, str) or not provider_id.strip():
        raise AIProviderError("AI provider must expose a non-empty provider_id")

    try:
        raw_output = provider.analyze(deepcopy(canonical_context))
        # Detach provider-owned objects before validating or returning them.
        detached_output = deepcopy(raw_output)
    except AIProviderError:
        raise
    except Exception as exc:
        raise AIProviderError("AI provider failed") from exc

    analysis = validate_ai_output(
        canonical_context,
        detached_output,
        source_result=result,
    )
    mode = "MOCK/DEMO" if provider_id == "mock" else "PROVIDER"
    return {
        "provider_id": provider_id,
        "mode": mode,
        "analysis": analysis,
    }
