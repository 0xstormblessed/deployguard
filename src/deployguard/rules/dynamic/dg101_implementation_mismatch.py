"""DG-101: Implementation Slot Mismatch rule."""

from deployguard.constants import EIP1967_IMPLEMENTATION_SLOT
from deployguard.models.core import Address
from deployguard.models.dynamic import ProxyState
from deployguard.models.rules import Rule, RuleCategory, RuleViolation, Severity

RULE_DG_101 = Rule(
    rule_id="DG-101",
    name="Implementation Slot Mismatch",
    description="The implementation address in the EIP-1967 slot does not match the expected address.",
    severity=Severity.CRITICAL,
    category=RuleCategory.DYNAMIC,
    references=[
        "https://eips.ethereum.org/EIP-1967",
        "https://docs.openzeppelin.com/upgrades-plugins/1.x/proxies",
    ],
    remediation=(
        "Verify the deployment transaction was not front-run. "
        "If the mismatch is unexpected, DO NOT interact with this proxy. "
        "Investigate the contract at the actual implementation address to determine if it's malicious."
    ),
)


def check_implementation_mismatch(
    proxy_state: ProxyState, expected_impl: Address
) -> RuleViolation | None:
    """Check if implementation address matches expected.

    Args:
        proxy_state: Current proxy state from chain
        expected_impl: Expected implementation address

    Returns:
        RuleViolation if mismatch detected, None otherwise
    """
    actual_impl = proxy_state.implementation_slot.decoded_address

    if actual_impl and actual_impl.lower() != expected_impl.lower():
        return RuleViolation(
            rule=RULE_DG_101,
            severity=Severity.CRITICAL,
            message=(f"Implementation mismatch: expected {expected_impl}, " f"found {actual_impl}"),
            recommendation=RULE_DG_101.remediation,
            storage_data=proxy_state.implementation_slot,
            context={
                "expected": str(expected_impl),
                "actual": str(actual_impl),
                "slot": EIP1967_IMPLEMENTATION_SLOT,
                "proxy_address": str(proxy_state.proxy_address),
                "block_number": proxy_state.implementation_slot.block_number,
            },
        )
    return None
