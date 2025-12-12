"""Configuration-related rules for deployment scripts."""

from deployguard.rules.config.hardcoded_address import RULE_HARDCODED_ADDRESS, rule_hardcoded_address
from deployguard.rules.registry import registry

# Register all config rules
registry.register_static(rule_hardcoded_address)

__all__ = [
    "RULE_HARDCODED_ADDRESS",
    "rule_hardcoded_address",
]
