"""Testing coverage rules for deployment scripts."""

from deployguard.rules.registry import registry
from deployguard.rules.testing.no_test import RULE_NO_TEST, rule_no_test
from deployguard.rules.testing.test_no_run import RULE_TEST_NO_RUN, rule_test_no_run

# Register all testing rules
registry.register_static(rule_no_test)
registry.register_static(rule_test_no_run)

__all__ = [
    "RULE_NO_TEST",
    "RULE_TEST_NO_RUN",
    "rule_no_test",
    "rule_test_no_run",
]
