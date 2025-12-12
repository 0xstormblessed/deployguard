"""ADMIN_MISMATCH: Admin Slot Mismatch rule."""

from deployguard.models.core import Address
from deployguard.models.dynamic import ProxyState
from deployguard.models.rules import Rule, RuleCategory, RuleViolation, Severity
from deployguard.rules.base import DynamicRule

RULE_ADMIN_MISMATCH = Rule(
    rule_id="ADMIN_MISMATCH",
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


class AdminMismatchRule(DynamicRule):
    """ADMIN_MISMATCH: Check for admin slot mismatch.

    Verifies that the admin address stored in the EIP-1967 admin slot
    matches the expected admin address.
    """

    async def check(
        self,
        proxy_state: ProxyState,
        expected_impl: str,
        expected_admin: str | None = None,
    ) -> list[RuleViolation]:
        """Check if admin address matches expected.

        Args:
            proxy_state: Current proxy state from chain
            expected_impl: Expected implementation address (unused)
            expected_admin: Expected admin address (None to skip check)

        Returns:
            List containing violation if mismatch detected, empty otherwise
        """
        violations = []

        if not expected_admin or not proxy_state.admin_slot:
            return violations

        actual_admin = proxy_state.admin_slot.decoded_address

        if actual_admin and actual_admin.lower() != expected_admin.lower():
            violations.append(
                RuleViolation(
                    rule=self.rule,
                    severity=self.rule.severity,
                    message=f"Admin mismatch: expected {expected_admin}, found {actual_admin}",
                    recommendation=self.rule.remediation,
                    storage_data=proxy_state.admin_slot,
                    context={
                        "expected": expected_admin,
                        "actual": str(actual_admin),
                        "proxy_address": str(proxy_state.proxy_address),
                        "block_number": proxy_state.admin_slot.block_number,
                    },
                )
            )

        return violations


# Instantiate rule for registration
rule_admin_mismatch = AdminMismatchRule(RULE_ADMIN_MISMATCH)


# Backward compatibility function (deprecated)
def check_admin_mismatch(
    proxy_state: ProxyState, expected_admin: Address | None
) -> RuleViolation | None:
    """Check if admin address matches expected.

    .. deprecated::
        Use AdminMismatchRule class instead.

    Args:
        proxy_state: Current proxy state from chain
        expected_admin: Expected admin address (None to skip check)

    Returns:
        RuleViolation if mismatch detected, None otherwise
    """
    import asyncio

    if not expected_admin:
        return None

    violations = asyncio.run(rule_admin_mismatch.check(proxy_state, "", str(expected_admin)))
    return violations[0] if violations else None
