"""Contract and privacy boundary for future AI-assisted investigation."""

from security.ai.adapter import adapt_investigation
from security.ai.contract import AIAnalysis, AIInput, AIOutput
from security.ai.provider import (
    AIProvider,
    AIProviderError,
    AIProviderTimeoutError,
)
from security.ai.providers import MockProvider
from security.ai.service import AIServiceResult, analyze_investigation
from security.ai.validation import (
    AIContractValidationError,
    validate_ai_input,
    validate_ai_output,
)

__all__ = [
    "AIAnalysis",
    "AIContractValidationError",
    "AIInput",
    "AIOutput",
    "MockProvider",
    "AIProvider",
    "AIProviderError",
    "AIProviderTimeoutError",
    "AIServiceResult",
    "analyze_investigation",
    "adapt_investigation",
    "validate_ai_input",
    "validate_ai_output",
]
