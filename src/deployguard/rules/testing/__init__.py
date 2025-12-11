"""Testing coverage rules for deployment scripts."""

from deployguard.rules.registry import registry
from deployguard.rules.testing.dg012_no_test import RULE_DG_012, rule_dg012
from deployguard.rules.testing.dg013_no_fork_test import RULE_DG_013, rule_dg013
from deployguard.rules.testing.dg014_test_no_run import RULE_DG_014, rule_dg014

# Register all testing rules
registry.register_static(rule_dg012)
registry.register_static(rule_dg013)
registry.register_static(rule_dg014)

__all__ = [
    "RULE_DG_012",
    "RULE_DG_013",
    "RULE_DG_014",
    "rule_dg012",
    "rule_dg013",
    "rule_dg014",
]
