"""Rule registry: which rules exist and in what order they run.

Order matters: DET-003 (account creation) uses the findings of DET-001 and
DET-002 as context, so it must run after them. To add a rule, write a class
that extends ``Rule`` and append it to ``RULE_CLASSES``; the engine, CLI and
report need no change.
"""

from __future__ import annotations

from typing import Optional

from security.detection.account_creation import AccountCreationRule
from security.detection.base import Rule
from security.detection.brute_force import BruteForceRule
from security.detection.config import DetectionConfig
from security.detection.powershell import PowerShellRule

RULE_CLASSES: tuple[type[Rule], ...] = (
    BruteForceRule,         # DET-001
    PowerShellRule,         # DET-002
    AccountCreationRule,    # DET-003 (needs DET-001 and DET-002 findings)
)
RULE_IDS: tuple[str, ...] = tuple(cls.rule_id for cls in RULE_CLASSES)


def default_rules(config: Optional[DetectionConfig] = None) -> list[Rule]:
    """Instantiate the built-in rules with their section of ``config``."""
    config = config or DetectionConfig()
    return [
        BruteForceRule(config.brute_force),
        PowerShellRule(config.powershell),
        AccountCreationRule(config.account_creation),
    ]
