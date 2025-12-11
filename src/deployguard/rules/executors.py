"""Rule executors for static and dynamic analysis.

This module provides executor classes that discover rules from the registry
and execute them with proper error handling and configuration support.

The executor pattern allows rules to be added by simply registering them,
without modifying analyzer code (Open/Closed Principle).
"""

import warnings

from deployguard.config import DeployGuardConfig
from deployguard.models.dynamic import ProxyState
from deployguard.models.rules import RuleViolation
from deployguard.models.static import ScriptAnalysis
from deployguard.rules.registry import registry


class StaticRuleExecutor:
    """Execute static analysis rules from registry.

    This executor discovers and runs all enabled static rules from the registry.
    It supports:
    - Config-based rule filtering (enabled/disabled)
    - Severity overrides
    - Per-rule error handling (failures don't stop execution)

    Example:
        >>> executor = StaticRuleExecutor(config)
        >>> violations = executor.execute(script_analysis)
    """

    def __init__(self, config: DeployGuardConfig | None = None):
        """Initialize static rule executor.

        Args:
            config: Configuration for rule filtering and overrides.
                   If None, uses default config with all rules enabled.
        """
        self.config = config or DeployGuardConfig()

    def execute(self, analysis: ScriptAnalysis) -> list[RuleViolation]:
        """Execute all enabled static rules from registry.

        Args:
            analysis: Parsed deployment script analysis

        Returns:
            List of all rule violations found across all executed rules

        Note:
            If a rule raises an exception, a warning is logged and execution
            continues with remaining rules. This ensures one bad rule doesn't
            stop the entire analysis.
        """
        violations = []

        # Get rules from registry (respects config filters)
        rules = registry.get_static_rules(
            enabled=self.config.enabled_rules or None,
            disabled=self.config.disabled_rules or None,
        )

        # Execute each rule
        for rule in rules:
            try:
                rule_violations = rule.check(analysis)

                # Apply severity overrides from config
                for v in rule_violations:
                    if v.rule.rule_id in self.config.severity_overrides:
                        v.severity = self.config.severity_overrides[v.rule.rule_id]

                violations.extend(rule_violations)

            except Exception as e:
                # Log warning but continue with other rules
                warnings.warn(
                    f"Rule {rule.rule.rule_id} failed: {e}",
                    stacklevel=2
                )

        return violations


class DynamicRuleExecutor:
    """Execute dynamic analysis rules from registry.

    This executor discovers and runs all enabled dynamic rules from the registry.
    It supports:
    - Config-based rule filtering (enabled/disabled)
    - Severity overrides
    - Per-rule error handling (failures don't stop execution)
    - Async execution

    Example:
        >>> executor = DynamicRuleExecutor(config)
        >>> violations = await executor.execute(proxy_state, expected_impl)
    """

    def __init__(self, config: DeployGuardConfig | None = None):
        """Initialize dynamic rule executor.

        Args:
            config: Configuration for rule filtering and overrides.
                   If None, uses default config with all rules enabled.
        """
        self.config = config or DeployGuardConfig()

    async def execute(
        self,
        proxy_state: ProxyState,
        expected_impl: str,
        expected_admin: str | None = None,
    ) -> list[RuleViolation]:
        """Execute all enabled dynamic rules from registry.

        Args:
            proxy_state: Current proxy state from blockchain
            expected_impl: Expected implementation address
            expected_admin: Expected admin address (optional)

        Returns:
            List of all rule violations found across all executed rules

        Note:
            If a rule raises an exception, a warning is logged and execution
            continues with remaining rules. This ensures one bad rule doesn't
            stop the entire analysis.
        """
        violations = []

        # Get rules from registry (respects config filters)
        rules = registry.get_dynamic_rules(
            enabled=self.config.enabled_rules or None,
            disabled=self.config.disabled_rules or None,
        )

        # Execute each rule
        for rule in rules:
            try:
                rule_violations = await rule.check(
                    proxy_state, expected_impl, expected_admin
                )

                # Apply severity overrides from config
                for v in rule_violations:
                    if v.rule.rule_id in self.config.severity_overrides:
                        v.severity = self.config.severity_overrides[v.rule.rule_id]

                violations.extend(rule_violations)

            except Exception as e:
                # Log warning but continue with other rules
                warnings.warn(
                    f"Rule {rule.rule.rule_id} failed: {e}",
                    stacklevel=2
                )

        return violations
