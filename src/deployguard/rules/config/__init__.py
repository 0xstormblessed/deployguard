"""Configuration-related rules for deployment scripts."""

from deployguard.rules.config.dg020_hardcoded_address import RULE_DG_020, rule_dg020
from deployguard.rules.registry import registry

# Register all config rules
registry.register_static(rule_dg020)

__all__ = [
    "RULE_DG_020",
    "rule_dg020",
]
