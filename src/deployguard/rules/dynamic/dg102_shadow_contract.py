"""DG-102: Shadow Contract Detection rule."""

from deployguard.models.dynamic import BytecodeAnalysis, ProxyState
from deployguard.models.rules import Rule, RuleCategory, RuleViolation, Severity

RULE_DG_102 = Rule(
    rule_id="DG-102",
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


def check_shadow_contract(
    proxy_state: ProxyState, bytecode_analysis: BytecodeAnalysis
) -> RuleViolation | None:
    """Check if implementation contract is a suspected shadow proxy.

    Args:
        proxy_state: Current proxy state from chain
        bytecode_analysis: Analysis of implementation contract bytecode

    Returns:
        RuleViolation if shadow contract detected, None otherwise
    """
    if not bytecode_analysis.has_delegatecall:
        return None

    return RuleViolation(
        rule=RULE_DG_102,
        severity=Severity.HIGH,
        message=("Suspected shadow contract: implementation contains DELEGATECALL opcode"),
        recommendation=RULE_DG_102.remediation,
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
