"""AI contract boundary for Sentinel DFIR.

This package defines input adaptation and output validation only. It does not
call an AI provider or modify Security investigation results.
"""

from security.ai.adapter import adapt_investigation
from security.ai.validation import (
    AIContractValidationError,
    validate_ai_input,
    validate_ai_output,
)

__all__ = [
    "AIContractValidationError",
    "adapt_investigation",
    "validate_ai_input",
    "validate_ai_output",
]
