"""SHADOW_CONTRACT: Shadow Contract Detection rule."""

from deployguard.models.dynamic import BytecodeAnalysis, ProxyState
from deployguard.models.rules import Rule, RuleCategory, RuleViolation, Severity
from deployguard.rules.base import DynamicRule

RULE_SHADOW_CONTRACT = Rule(
    rule_id="SHADOW_CONTRACT",
    name="Shadow Contract Detection",
    description=(
        "The contract in the implementation slot contains DELEGATECALL, "
        "suggesting it may be a malicious middleman proxy."
    ),
    severity=Severity.HIGH,
    category=RuleCategory.DYNAMIC,
    references=[
        "https://eips.ethereum.org/EIP-1967",
        "https://blog.openzeppelin.com/proxy-patterns",
    ],
    remediation=(
        "A contract with DELEGATECALL in the implementation slot may be a "
        "shadow proxy (middleman attack). Investigate the bytecode at the "
        "implementation address. If this is unexpected, DO NOT interact with "
        "the proxy until the issue is resolved."
    ),
)


class ShadowContractRule(DynamicRule):
    """SHADOW_CONTRACT: Check for shadow contracts (implementation contains DELEGATECALL).

    Detects when the implementation contract contains DELEGATECALL opcode,
    which may indicate a malicious middleman proxy pattern.
    """

    async def check(
        self,
        proxy_state: ProxyState,
        expected_impl: str,
        expected_admin: str | None = None,
    ) -> list[RuleViolation]:
        """Check if implementation contract is a suspected shadow proxy.

        Args:
            proxy_state: Current proxy state from chain
            expected_impl: Expected implementation address (unused)
            expected_admin: Expected admin address (unused)

        Returns:
            List containing violation if shadow contract detected, empty otherwise

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
                    message="Suspected shadow contract: implementation contains DELEGATECALL opcode",
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
rule_shadow_contract = ShadowContractRule(RULE_SHADOW_CONTRACT)


# Backward compatibility function (deprecated)
def check_shadow_contract(
    proxy_state: ProxyState, bytecode_analysis: BytecodeAnalysis
) -> RuleViolation | None:
    """Check if implementation contract is a suspected shadow proxy.

    .. deprecated::
        Use ShadowContractRule class instead.

    Args:
        proxy_state: Current proxy state from chain
        bytecode_analysis: Analysis of implementation contract bytecode

    Returns:
        RuleViolation if shadow contract detected, None otherwise
    """
    if not bytecode_analysis.has_delegatecall:
        return None

    return RuleViolation(
        rule=RULE_SHADOW_CONTRACT,
        severity=Severity.HIGH,
        message="Suspected shadow contract: implementation contains DELEGATECALL opcode",
        recommendation=RULE_SHADOW_CONTRACT.remediation,
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
