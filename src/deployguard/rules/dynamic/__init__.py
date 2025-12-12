"""Dynamic analysis rules for proxy verification."""

from deployguard.rules.dynamic.impl_mismatch import (
    RULE_IMPL_MISMATCH,
    check_implementation_mismatch,
    rule_impl_mismatch,
)
from deployguard.rules.dynamic.shadow_contract import (
    RULE_SHADOW_CONTRACT,
    check_shadow_contract,
    rule_shadow_contract,
)
from deployguard.rules.dynamic.uninitialized_proxy import (
    RULE_UNINITIALIZED_PROXY,
    check_uninitialized_proxy,
    rule_uninitialized_proxy,
)
from deployguard.rules.dynamic.admin_mismatch import (
    RULE_ADMIN_MISMATCH,
    check_admin_mismatch,
    rule_admin_mismatch,
)
from deployguard.rules.dynamic.non_standard_proxy import (
    RULE_NON_STANDARD_PROXY,
    check_non_standard_proxy,
    rule_non_standard_proxy,
)
from deployguard.rules.registry import registry

# Register all dynamic rules
registry.register_dynamic(rule_impl_mismatch)
registry.register_dynamic(rule_shadow_contract)
registry.register_dynamic(rule_uninitialized_proxy)
registry.register_dynamic(rule_admin_mismatch)
registry.register_dynamic(rule_non_standard_proxy)

__all__ = [
    # Rule metadata
    "RULE_IMPL_MISMATCH",
    "RULE_SHADOW_CONTRACT",
    "RULE_UNINITIALIZED_PROXY",
    "RULE_ADMIN_MISMATCH",
    "RULE_NON_STANDARD_PROXY",
    # Rule instances
    "rule_impl_mismatch",
    "rule_shadow_contract",
    "rule_uninitialized_proxy",
    "rule_admin_mismatch",
    "rule_non_standard_proxy",
    # Deprecated functions (for backward compatibility)
    "check_implementation_mismatch",
    "check_shadow_contract",
    "check_uninitialized_proxy",
    "check_admin_mismatch",
    "check_non_standard_proxy",
]
