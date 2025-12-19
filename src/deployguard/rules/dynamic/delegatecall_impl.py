"""DELEGATECALL_IMPL: Implementation Contains DELEGATECALL rule."""

from deployguard.models.dynamic import BytecodeAnalysis, ProxyState
from deployguard.models.rules import Rule, RuleCategory, RuleViolation, Severity
from deployguard.rules.base import DynamicRule

RULE_DELEGATECALL_IMPL = Rule(
    rule_id="DELEGATECALL_IMPL",
    name="Implementation Contains DELEGATECALL",
    description=(
        "The contract in the implementation slot contains DELEGATECALL. "
        "This is expected for UUPS proxies but may indicate a middleman proxy in other patterns."
    ),
    severity=Severity.INFO,
    category=RuleCategory.DYNAMIC,
    references=[
        "https://eips.ethereum.org/EIPS/eip-1822",
        "https://blog.openzeppelin.com/proxy-patterns",
    ],
    remediation=(
        "DELEGATECALL in the implementation is expected for UUPS proxies (upgrade logic). "
        "Verify this matches your expected proxy pattern. For non-UUPS patterns, investigate "
        "the bytecode to ensure it's not a malicious middleman proxy."
    ),
)


class DelegatecallImplRule(DynamicRule):
    """DELEGATECALL_IMPL: Check if implementation contains DELEGATECALL.

    Detects when the implementation contract contains DELEGATECALL opcode.
    This is expected for UUPS proxies but informational for other patterns.
    """

    async def check(
        self,
        proxy_state: ProxyState,
        expected_impl: str,
        expected_admin: str | None = None,
    ) -> list[RuleViolation]:
        """Check if implementation contract contains DELEGATECALL.

        Args:
            proxy_state: Current proxy state from chain
            expected_impl: Expected implementation address (unused)
            expected_admin: Expected admin address (unused)

        Returns:
            List containing violation if DELEGATECALL detected, empty otherwise

        Note:
            This rule requires ProxyState to include implementation_bytecode_analysis.
            If bytecode_analysis is not available, the rule returns no violations.
        """
        violations = []

        # Check if bytecode analysis is available (requires ProxyState enhancement)
        bytecode_analysis = getattr(proxy_state, "implementation_bytecode_analysis", None)
        if not bytecode_analysis:
            # Cannot check without bytecode analysis
            return violations

        if bytecode_analysis.has_delegatecall:
            violations.append(
                RuleViolation(
                    rule=self.rule,
                    severity=self.rule.severity,
                    message="Implementation contains DELEGATECALL opcode",
                    recommendation=self.rule.remediation,
                    bytecode_data=bytecode_analysis,
                    storage_data=proxy_state.implementation_slot,
                    context={
                        "implementation_address": str(bytecode_analysis.address),
                        "is_proxy_pattern": bytecode_analysis.is_proxy_pattern,
                        "has_selfdestruct": bytecode_analysis.has_selfdestruct,
                        "has_create": bytecode_analysis.has_create,
                        "has_create2": bytecode_analysis.has_create2,
                        "risk_indicators": bytecode_analysis.risk_indicators,
                    },
                )
            )

        return violations


# Instantiate rule for registration
rule_delegatecall_impl = DelegatecallImplRule(RULE_DELEGATECALL_IMPL)
