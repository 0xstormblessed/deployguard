"""DG-105: Non-Standard Proxy Pattern rule."""

from deployguard.models.dynamic import ProxyStandard, ProxyState
from deployguard.models.rules import Rule, RuleCategory, RuleViolation, Severity

RULE_DG_105 = Rule(
    rule_id="DG-105",
    name="Non-Standard Proxy Pattern",
    description="Proxy uses non-EIP-1967 storage slots.",
    severity=Severity.INFO,
    category=RuleCategory.DYNAMIC,
    references=[
        "https://eips.ethereum.org/EIP-1967",
        "https://eips.ethereum.org/EIP-1822",
        "https://eips.ethereum.org/EIP-1167",
    ],
    remediation=(
        "The proxy does not appear to use standard EIP-1967 storage slots. "
        "This may indicate a custom proxy implementation or a different proxy "
        "standard (e.g., EIP-1822 UUPS, EIP-1167 minimal proxy). Verify that "
        "the proxy standard matches your expectations and that it's properly "
        "configured."
    ),
)


def check_non_standard_proxy(proxy_state: ProxyState) -> RuleViolation | None:
    """Check if proxy uses non-standard storage slots.

    Args:
        proxy_state: Current proxy state from chain

    Returns:
        RuleViolation if non-standard proxy detected, None otherwise
    """
    if proxy_state.proxy_standard == ProxyStandard.UNKNOWN:
        zero_slot = "0x" + "0" * 64
        impl_slot_empty = proxy_state.implementation_slot.value == zero_slot

        return RuleViolation(
            rule=RULE_DG_105,
            severity=Severity.INFO,
            message="Proxy does not use standard EIP-1967 storage slots",
            recommendation=RULE_DG_105.remediation,
            context={
                "proxy_address": str(proxy_state.proxy_address),
                "proxy_standard": proxy_state.proxy_standard.value,
                "implementation_slot_empty": impl_slot_empty,
                "is_initialized": proxy_state.is_initialized,
            },
        )
    return None
