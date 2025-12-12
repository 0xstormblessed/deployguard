"""Rule registry for managing and filtering rules.

The registry provides a central location for all static and dynamic rules.
It supports filtering by category, severity, and enabled/disabled state.
"""

from typing import Callable

from deployguard.models.rules import RuleCategory, Severity
from deployguard.rules.base import DynamicRule, StaticRule


class RuleRegistry:
    """Central registry for all DeployGuard rules.

    The registry maintains separate collections for static and dynamic rules,
    and provides filtering capabilities for rule selection.

    Attributes:
        _static_rules: Dictionary of static rules by rule_id
        _dynamic_rules: Dictionary of dynamic rules by rule_id
    """

    def __init__(self) -> None:
        """Initialize empty rule registry."""
        self._static_rules: dict[str, StaticRule] = {}
        self._dynamic_rules: dict[str, DynamicRule] = {}

    def register_static(self, rule: StaticRule) -> None:
        """Register a static analysis rule.

        Args:
            rule: Static rule to register

        Raises:
            ValueError: If rule with same ID already registered
        """
        if rule.rule.rule_id in self._static_rules:
            raise ValueError(f"Static rule {rule.rule.rule_id} already registered")
        self._static_rules[rule.rule.rule_id] = rule

    def register_dynamic(self, rule: DynamicRule) -> None:
        """Register a dynamic analysis rule.

        Args:
            rule: Dynamic rule to register

        Raises:
            ValueError: If rule with same ID already registered
        """
        if rule.rule.rule_id in self._dynamic_rules:
            raise ValueError(f"Dynamic rule {rule.rule.rule_id} already registered")
        self._dynamic_rules[rule.rule.rule_id] = rule

    def get_static_rules(
        self,
        enabled: list[str] | None = None,
        disabled: list[str] | None = None,
        categories: list[RuleCategory] | None = None,
        min_severity: Severity | None = None,
    ) -> list[StaticRule]:
        """Get filtered list of static rules.

        Args:
            enabled: If provided, only return rules with these IDs
            disabled: Rule IDs to exclude
            categories: If provided, only return rules in these categories
            min_severity: Only return rules at or above this severity

        Returns:
            Filtered list of static rules
        """
        rules = list(self._static_rules.values())

        # Filter by enabled list (if provided, only include these)
        if enabled:
            rules = [r for r in rules if r.rule.rule_id in enabled]

        # Filter out disabled rules
        if disabled:
            rules = [r for r in rules if r.rule.rule_id not in disabled]

        # Filter by category
        if categories:
            rules = [r for r in rules if r.rule.category in categories]

        # Filter by severity
        if min_severity:
            severity_order = {
                Severity.INFO: 0,
                Severity.LOW: 1,
                Severity.MEDIUM: 2,
                Severity.HIGH: 3,
                Severity.CRITICAL: 4,
            }
            min_level = severity_order[min_severity]
            rules = [r for r in rules if severity_order[r.rule.severity] >= min_level]

        return rules

    def get_dynamic_rules(
        self,
        enabled: list[str] | None = None,
        disabled: list[str] | None = None,
        categories: list[RuleCategory] | None = None,
        min_severity: Severity | None = None,
    ) -> list[DynamicRule]:
        """Get filtered list of dynamic rules.

        Args:
            enabled: If provided, only return rules with these IDs
            disabled: Rule IDs to exclude
            categories: If provided, only return rules in these categories
            min_severity: Only return rules at or above this severity

        Returns:
            Filtered list of dynamic rules
        """
        rules = list(self._dynamic_rules.values())

        # Filter by enabled list (if provided, only include these)
        if enabled:
            rules = [r for r in rules if r.rule.rule_id in enabled]

        # Filter out disabled rules
        if disabled:
            rules = [r for r in rules if r.rule.rule_id not in disabled]

        # Filter by category
        if categories:
            rules = [r for r in rules if r.rule.category in categories]

        # Filter by severity
        if min_severity:
            severity_order = {
                Severity.INFO: 0,
                Severity.LOW: 1,
                Severity.MEDIUM: 2,
                Severity.HIGH: 3,
                Severity.CRITICAL: 4,
            }
            min_level = severity_order[min_severity]
            rules = [r for r in rules if severity_order[r.rule.severity] >= min_level]

        return rules

    def get_rule_by_id(self, rule_id: str) -> StaticRule | DynamicRule | None:
        """Get a specific rule by its ID.

        Args:
            rule_id: The rule ID to look up

        Returns:
            The rule if found, None otherwise
        """
        return self._static_rules.get(rule_id) or self._dynamic_rules.get(rule_id)

    def list_all_rules(self) -> dict[str, StaticRule | DynamicRule]:
        """Get all registered rules.

        Returns:
            Dictionary mapping rule_id to rule instance
        """
        return {**self._static_rules, **self._dynamic_rules}


# Global registry instance
registry = RuleRegistry()


def static_rule(rule_id: str, **kwargs: dict) -> Callable:
    """Decorator to register a static rule class.

    Usage:
        @static_rule(
            rule_id="NON_ATOMIC_INIT",
            name="Non-Atomic Init",
            description="...",
            severity=Severity.CRITICAL,
            category=RuleCategory.PROXY,
            remediation="..."
        )
        class NonAtomicInitRule(StaticRule):
            ...

    Args:
        rule_id: Unique rule identifier
        **kwargs: Additional Rule fields

    Returns:
        Decorator function
    """
    from deployguard.models.rules import Rule

    def decorator(cls: type[StaticRule]) -> type[StaticRule]:
        rule_def = Rule(rule_id=rule_id, **kwargs)
        instance = cls(rule_def)
        registry.register_static(instance)
        return cls

    return decorator


def dynamic_rule(rule_id: str, **kwargs: dict) -> Callable:
    """Decorator to register a dynamic rule class.

    Usage:
        @dynamic_rule(
            rule_id="IMPL_MISMATCH",
            name="Implementation Mismatch",
            description="...",
            severity=Severity.CRITICAL,
            category=RuleCategory.DYNAMIC,
            remediation="..."
        )
        class ImplMismatchRule(DynamicRule):
            ...

    Args:
        rule_id: Unique rule identifier
        **kwargs: Additional Rule fields

    Returns:
        Decorator function
    """
    from deployguard.models.rules import Rule

    def decorator(cls: type[DynamicRule]) -> type[DynamicRule]:
        rule_def = Rule(rule_id=rule_id, **kwargs)
        instance = cls(rule_def)
        registry.register_dynamic(instance)
        return cls

    return decorator
