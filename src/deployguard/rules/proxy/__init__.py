"""Proxy-related security rules (CPIMP detection)."""

from deployguard.rules.proxy.non_atomic_init import RULE_NON_ATOMIC_INIT, rule_non_atomic_init
from deployguard.rules.proxy.hardcoded_impl import RULE_HARDCODED_IMPL, rule_hardcoded_impl
from deployguard.rules.proxy.missing_impl_validation import RULE_MISSING_IMPL_VALIDATION, rule_missing_impl_validation
from deployguard.rules.registry import registry

# Register all proxy rules
registry.register_static(rule_non_atomic_init)
registry.register_static(rule_hardcoded_impl)
registry.register_static(rule_missing_impl_validation)

__all__ = [
    "RULE_NON_ATOMIC_INIT",
    "RULE_HARDCODED_IMPL",
    "RULE_MISSING_IMPL_VALIDATION",
    "rule_non_atomic_init",
    "rule_hardcoded_impl",
    "rule_missing_impl_validation",
]
