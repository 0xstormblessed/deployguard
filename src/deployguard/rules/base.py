"""Base classes for the rule system.

This module defines the abstract base classes for static and dynamic analysis rules.
Rules implement a check() method that analyzes script data or on-chain state and
returns a list of violations.
"""

from abc import ABC, abstractmethod

from deployguard.models.dynamic import ProxyState
from deployguard.models.rules import Rule, RuleViolation
from deployguard.models.static import ScriptAnalysis


class StaticRule(ABC):
    """Abstract base class for static analysis rules.

    Static rules analyze deployment scripts before deployment to detect:
    - CPIMP vulnerabilities (non-atomic initialization, separated transactions)
    - Security issues (private keys, access control)
    - Configuration problems (hardcoded addresses)
    - Missing test coverage

    Attributes:
        rule: Rule metadata (ID, name, description, severity, etc.)
    """

    def __init__(self, rule: Rule):
        """Initialize static rule.

        Args:
            rule: Rule metadata defining the check
        """
        self.rule = rule

    @abstractmethod
    def check(self, analysis: ScriptAnalysis) -> list[RuleViolation]:
        """Execute the rule against a parsed deployment script.

        Args:
            analysis: Parsed and analyzed deployment script

        Returns:
            List of violations found (empty if none)

        Note:
            All returned violations MUST include a recommendation field
            to help developers fix the issue.
        """
        pass


class DynamicRule(ABC):
    """Abstract base class for dynamic analysis rules.

    Dynamic rules analyze on-chain state after deployment to verify:
    - Implementation address matches expected
    - No shadow contracts (unexpected delegatecall)
    - Proxy is properly initialized
    - Admin address matches expected
    - Proxy follows standard patterns

    Attributes:
        rule: Rule metadata (ID, name, description, severity, etc.)
    """

    def __init__(self, rule: Rule):
        """Initialize dynamic rule.

        Args:
            rule: Rule metadata defining the check
        """
        self.rule = rule

    @abstractmethod
    async def check(
        self,
        proxy_state: ProxyState,
        expected_impl: str,
        expected_admin: str | None = None,
    ) -> list[RuleViolation]:
        """Execute the rule against on-chain proxy state.

        Args:
            proxy_state: Current state of the proxy from chain
            expected_impl: Expected implementation address
            expected_admin: Expected admin address (optional)

        Returns:
            List of violations found (empty if none)

        Note:
            All returned violations MUST include a recommendation field
            to help developers fix the issue.
        """
        pass
