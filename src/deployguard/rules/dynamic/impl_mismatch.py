"""IMPL_MISMATCH: Implementation Slot Mismatch rule."""

from deployguard.constants import EIP1967_IMPLEMENTATION_SLOT
from deployguard.models.core import Address
from deployguard.models.dynamic import ProxyState
from deployguard.models.rules import Rule, RuleCategory, RuleViolation, Severity
from deployguard.rules.base import DynamicRule

RULE_IMPL_MISMATCH = Rule(
    rule_id="IMPL_MISMATCH",
    name="Implementation Slot Mismatch",
    description="The implementation address in the EIP-1967 slot does not match the expected address.",
    severity=Severity.CRITICAL,
    category=RuleCategory.DYNAMIC,
    references=[
        "https://eips.ethereum.org/EIPS/eip-1967",
        "https://docs.openzeppelin.com/upgrades-plugins/1.x/proxies",
    ],
    hack_references=[
        "https://rekt.news/uspd-rekt/",
        "https://dedaub.com/blog/the-cpimp-attack-an-insanely-far-reaching-vulnerability-successfully-mitigated/",
    ],
    real_world_context=(
        "Implementation mismatches can indicate a CPIMP (Clandestine Proxy In the Middle of Proxy) attack. "
        "Attackers monitor mempools for proxy deployments, then front-run to initialize with a malicious "
        "implementation or gain admin control. Dedaub identified CPIMP as affecting thousands of contracts "
        "across multiple chains. Always verify the on-chain implementation matches your expected deployment."
    ),
    remediation=(
        "Verify the deployment transaction was not front-run. "
        "If the mismatch is unexpected, DO NOT interact with this proxy. "
        "Investigate the contract at the actual implementation address to determine if it's malicious."
    ),
)


class ImplementationMismatchRule(DynamicRule):
    """IMPL_MISMATCH: Check for implementation slot mismatch.

    Verifies that the implementation address stored in the EIP-1967 implementation
    slot matches the expected implementation address.
    """

    async def check(
        self,
        proxy_state: ProxyState,
        expected_impl: str,
        expected_admin: str | None = None,
    ) -> list[RuleViolation]:
        """Check if implementation address matches expected.

        Args:
            proxy_state: Current proxy state from chain
            expected_impl: Expected implementation address
            expected_admin: Expected admin address (unused for this rule)

        Returns:
            List containing violation if mismatch detected, empty list otherwise
        """
        violations = []
        actual_impl = proxy_state.implementation_slot.decoded_address

        if actual_impl and actual_impl.lower() != expected_impl.lower():
            violations.append(
                RuleViolation(
                    rule=self.rule,
                    severity=self.rule.severity,
                    message=f"Implementation mismatch: expected {expected_impl}, found {actual_impl}",
                    recommendation=self.rule.remediation,
                    storage_data=proxy_state.implementation_slot,
                    context={
                        "expected": expected_impl,
                        "actual": str(actual_impl),
                        "slot": EIP1967_IMPLEMENTATION_SLOT,
                        "proxy_address": str(proxy_state.proxy_address),
                        "block_number": proxy_state.implementation_slot.block_number,
                    },
                )
            )

        return violations


# Instantiate rule for registration
rule_impl_mismatch = ImplementationMismatchRule(RULE_IMPL_MISMATCH)


# Backward compatibility function (deprecated)
def check_implementation_mismatch(
    proxy_state: ProxyState, expected_impl: Address
) -> RuleViolation | None:
    """Check if implementation address matches expected.

    .. deprecated::
        Use ImplementationMismatchRule class instead.

    Args:
        proxy_state: Current proxy state from chain
        expected_impl: Expected implementation address

    Returns:
        RuleViolation if mismatch detected, None otherwise
    """
    import asyncio

    violations = asyncio.run(rule_impl_mismatch.check(proxy_state, str(expected_impl), None))
    return violations[0] if violations else None
