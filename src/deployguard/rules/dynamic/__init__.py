"""Dynamic analysis rules for proxy verification."""

from deployguard.rules.dynamic.dg101_implementation_mismatch import (
    RULE_DG_101,
    check_implementation_mismatch,
    rule_dg101,
)
from deployguard.rules.dynamic.dg102_shadow_contract import (
    RULE_DG_102,
    check_shadow_contract,
    rule_dg102,
)
from deployguard.rules.dynamic.dg103_uninitialized import (
    RULE_DG_103,
    check_uninitialized_proxy,
    rule_dg103,
)
from deployguard.rules.dynamic.dg104_admin_mismatch import (
    RULE_DG_104,
    check_admin_mismatch,
    rule_dg104,
)
from deployguard.rules.dynamic.dg105_non_standard import (
    RULE_DG_105,
    check_non_standard_proxy,
    rule_dg105,
)
from deployguard.rules.registry import registry

# Register all dynamic rules
registry.register_dynamic(rule_dg101)
registry.register_dynamic(rule_dg102)
registry.register_dynamic(rule_dg103)
registry.register_dynamic(rule_dg104)
registry.register_dynamic(rule_dg105)

__all__ = [
    # Rule metadata
    "RULE_DG_101",
    "RULE_DG_102",
    "RULE_DG_103",
    "RULE_DG_104",
    "RULE_DG_105",
    # Rule instances
    "rule_dg101",
    "rule_dg102",
    "rule_dg103",
    "rule_dg104",
    "rule_dg105",
    # Deprecated functions (for backward compatibility)
    "check_implementation_mismatch",
    "check_shadow_contract",
    "check_uninitialized_proxy",
    "check_admin_mismatch",
    "check_non_standard_proxy",
]
