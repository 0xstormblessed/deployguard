"""DG-103: Uninitialized Proxy rule."""

from deployguard.models.dynamic import ProxyState
from deployguard.models.rules import Rule, RuleCategory, RuleViolation, Severity

RULE_DG_103 = Rule(
    rule_id="DG-103",
    name="Uninitialized Proxy",
    description="The implementation slot is empty (zero address), indicating an uninitialized proxy.",
    severity=Severity.HIGH,
    category=RuleCategory.DYNAMIC,
    references=[
        "https://eips.ethereum.org/EIP-1967",
        "https://docs.openzeppelin.com/upgrades-plugins/1.x/proxies",
    ],
    remediation=(
        "The proxy has not been initialized. Initialize the proxy by calling "
        "the initialization function with appropriate parameters. An uninitialized "
        "proxy cannot be used and may be vulnerable to front-running attacks."
    ),
)


def check_uninitialized_proxy(proxy_state: ProxyState) -> RuleViolation | None:
    """Check if proxy is uninitialized.

    Args:
        proxy_state: Current proxy state from chain

    Returns:
        RuleViolation if proxy is uninitialized, None otherwise
    """
    impl_value = proxy_state.implementation_slot.value
    zero_slot = "0x" + "0" * 64

    if impl_value == zero_slot:
        return RuleViolation(
            rule=RULE_DG_103,
            severity=Severity.HIGH,
            message="Proxy implementation slot is empty (uninitialized)",
            recommendation=RULE_DG_103.remediation,
            storage_data=proxy_state.implementation_slot,
            context={
                "proxy_address": str(proxy_state.proxy_address),
                "slot_value": str(impl_value),
                "block_number": proxy_state.implementation_slot.block_number,
            },
        )
    return None
