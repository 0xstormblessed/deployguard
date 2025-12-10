"""DG-104: Admin Slot Mismatch rule."""

from deployguard.models.core import Address
from deployguard.models.dynamic import ProxyState
from deployguard.models.rules import Rule, RuleCategory, RuleViolation, Severity

RULE_DG_104 = Rule(
    rule_id="DG-104",
    name="Admin Slot Mismatch",
    description="The admin address in the EIP-1967 admin slot does not match expected.",
    severity=Severity.MEDIUM,
    category=RuleCategory.DYNAMIC,
    references=[
        "https://eips.ethereum.org/EIP-1967",
        "https://docs.openzeppelin.com/upgrades-plugins/1.x/proxies",
    ],
    remediation=(
        "Verify the admin address is correct. If the mismatch is unexpected, "
        "investigate who has control of the admin address. The admin can upgrade "
        "the proxy implementation, so ensure it's set to a trusted address "
        "(e.g., multisig or governance contract)."
    ),
)


def check_admin_mismatch(
    proxy_state: ProxyState, expected_admin: Address | None
) -> RuleViolation | None:
    """Check if admin address matches expected.

    Args:
        proxy_state: Current proxy state from chain
        expected_admin: Expected admin address (None to skip check)

    Returns:
        RuleViolation if mismatch detected, None otherwise
    """
    if not expected_admin or not proxy_state.admin_slot:
        return None

    actual_admin = proxy_state.admin_slot.decoded_address

    if actual_admin and actual_admin.lower() != expected_admin.lower():
        return RuleViolation(
            rule=RULE_DG_104,
            severity=Severity.MEDIUM,
            message=(f"Admin mismatch: expected {expected_admin}, found {actual_admin}"),
            recommendation=RULE_DG_104.remediation,
            storage_data=proxy_state.admin_slot,
            context={
                "expected": str(expected_admin),
                "actual": str(actual_admin),
                "proxy_address": str(proxy_state.proxy_address),
                "block_number": proxy_state.admin_slot.block_number,
            },
        )
    return None
