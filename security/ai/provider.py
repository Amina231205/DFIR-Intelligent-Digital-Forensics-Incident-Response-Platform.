"""Synchronous interface and errors for local or future AI providers."""

from __future__ import annotations

from typing import Protocol

from security.ai.contract import AIInput, AIOutput


class AIProviderError(RuntimeError):
    """Raised when a provider cannot produce an AI response."""


class AIProviderTimeoutError(AIProviderError):
    """Raised when a provider operation exceeds its allowed time."""


class AIProvider(Protocol):
    """Synchronous provider API receiving only the minimized AI context."""

    provider_id: str

    def analyze(self, ai_input: AIInput) -> AIOutput:
        """Generate an untrusted response for application validation."""
