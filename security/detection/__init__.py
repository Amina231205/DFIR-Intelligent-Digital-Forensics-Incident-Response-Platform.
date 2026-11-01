"""Rule-based detection: ``detect_case(folder) -> DetectionResult``."""

from security.detection.base import Rule, RuleContext, RuleOutput
from security.detection.config import (
    AccountCreationConfig,
    BruteForceConfig,
    DetectionConfig,
    PowerShellConfig,
)
from security.detection.engine import detect_case, run_detection
from security.detection.ip_policy import IpClass, IpPolicy, classify_ip
from security.detection.report import format_detection
from security.detection.rules import RULE_IDS, default_rules

__all__ = [
    "AccountCreationConfig", "BruteForceConfig", "DetectionConfig", "IpClass",
    "IpPolicy", "PowerShellConfig", "RULE_IDS", "Rule", "RuleContext",
    "RuleOutput", "classify_ip", "default_rules", "detect_case",
    "format_detection", "run_detection",
]
