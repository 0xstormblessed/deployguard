"""Rule system for DeployGuard.

This module provides the rule engine for static and dynamic analysis of
deployment scripts. Rules are automatically registered when imported.

Available rule categories:
- Proxy rules: NON_ATOMIC_INIT, HARDCODED_IMPL, MISSING_IMPL_VALIDATION
- Security rules: PRIVATE_KEY_ENV, MISSING_OWNERSHIP_TRANSFER, DEPLOYER_ADMIN, UUPS_*
- Testing rules: NO_TEST, TEST_NO_RUN
- Config rules: HARDCODED_ADDRESS
- Dynamic rules: IMPL_MISMATCH, SHADOW_CONTRACT, UNINITIALIZED_PROXY, ADMIN_MISMATCH, NON_STANDARD_PROXY
"""

# Import base classes and registry
from deployguard.rules.base import DynamicRule, StaticRule
from deployguard.rules.executors import DynamicRuleExecutor, StaticRuleExecutor
from deployguard.rules.registry import dynamic_rule, registry, static_rule

# Import all rule modules to trigger registration
# The rule instances are created when modules are imported
import deployguard.rules.config  # noqa: F401
import deployguard.rules.dynamic  # noqa: F401
import deployguard.rules.proxy  # noqa: F401
import deployguard.rules.security  # noqa: F401
import deployguard.rules.testing  # noqa: F401

__all__ = [
    # Base classes
    "StaticRule",
    "DynamicRule",
    # Registry and decorators
    "registry",
    "static_rule",
    "dynamic_rule",
    # Executors
    "StaticRuleExecutor",
    "DynamicRuleExecutor",
]


def get_all_static_rules():
    """Get all registered static rules.

    Returns:
        List of all static rule instances
    """
    return registry.get_static_rules()


def get_all_dynamic_rules():
    """Get all registered dynamic rules.

    Returns:
        List of all dynamic rule instances
    """
    return registry.get_dynamic_rules()


def get_rule_by_id(rule_id: str):
    """Get a specific rule by ID.

    Args:
        rule_id: Rule identifier (e.g., "NON_ATOMIC_INIT", "IMPL_MISMATCH")

    Returns:
        Rule instance if found, None otherwise
    """
    return registry.get_rule_by_id(rule_id)


def list_all_rules():
    """List all registered rules.

    Returns:
        Dictionary mapping rule IDs to rule instances
    """
    return registry.list_all_rules()
