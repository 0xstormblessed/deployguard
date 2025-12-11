"""Proxy-related security rules (CPIMP detection)."""

from deployguard.rules.proxy.dg001_non_atomic import RULE_DG_001, rule_dg001
from deployguard.rules.proxy.dg002_separated import RULE_DG_002, rule_dg002
from deployguard.rules.proxy.dg003_hardcoded import RULE_DG_003, rule_dg003
from deployguard.rules.proxy.dg004_validation import RULE_DG_004, rule_dg004
from deployguard.rules.registry import registry

# Register all proxy rules
registry.register_static(rule_dg001)
registry.register_static(rule_dg002)
registry.register_static(rule_dg003)
registry.register_static(rule_dg004)

__all__ = [
    "RULE_DG_001",
    "RULE_DG_002",
    "RULE_DG_003",
    "RULE_DG_004",
    "rule_dg001",
    "rule_dg002",
    "rule_dg003",
    "rule_dg004",
]
