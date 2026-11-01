"""Evidence normalization: ``normalize_case(folder) -> NormalizationResult``."""

from security.normalization.normalizer import (
    event_sort_key,
    normalize_case,
    normalize_validated,
)

__all__ = ["event_sort_key", "normalize_case", "normalize_validated"]
