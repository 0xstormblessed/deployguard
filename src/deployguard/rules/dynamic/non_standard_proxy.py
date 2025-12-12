"""NON_STANDARD_PROXY: Non-Standard Proxy Pattern rule."""

from deployguard.models.dynamic import ProxyStandard, ProxyState
from deployguard.models.rules import Rule, RuleCategory, RuleViolation, Severity
from deployguard.rules.base import DynamicRule

RULE_NON_STANDARD_PROXY = Rule(
    rule_id="NON_STANDARD_PROXY",
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


class NonStandardProxyRule(DynamicRule):
    """NON_STANDARD_PROXY: Check for non-standard proxy patterns.

    Detects proxies that don't use standard EIP-1967 storage slots,
    which may indicate custom implementations or different proxy standards.
    """

    async def check(
        self,
        proxy_state: ProxyState,
        expected_impl: str,
        expected_admin: str | None = None,
    ) -> list[RuleViolation]:
        """Check if proxy uses non-standard storage slots.

        Args:
            proxy_state: Current proxy state from chain
            expected_impl: Expected implementation address (unused)
            expected_admin: Expected admin address (unused)

        Returns:
            List containing violation if non-standard proxy detected, empty otherwise
        """
        violations = []

        if proxy_state.proxy_standard == ProxyStandard.UNKNOWN:
            zero_slot = "0x" + "0" * 64
            impl_slot_empty = proxy_state.implementation_slot.value == zero_slot

            violations.append(
                RuleViolation(
                    rule=self.rule,
                    severity=self.rule.severity,
                    message="Proxy does not use standard EIP-1967 storage slots",
                    recommendation=self.rule.remediation,
                    context={
                        "proxy_address": str(proxy_state.proxy_address),
                        "proxy_standard": proxy_state.proxy_standard.value,
                        "implementation_slot_empty": impl_slot_empty,
                        "is_initialized": proxy_state.is_initialized,
                    },
                )
            )

        return violations


# Instantiate rule for registration
rule_non_standard_proxy = NonStandardProxyRule(RULE_NON_STANDARD_PROXY)


# Backward compatibility function (deprecated)
def check_non_standard_proxy(proxy_state: ProxyState) -> RuleViolation | None:
    """Check if proxy uses non-standard storage slots.

    .. deprecated::
        Use NonStandardProxyRule class instead.

    Args:
        proxy_state: Current proxy state from chain

    Returns:
        RuleViolation if non-standard proxy detected, None otherwise
    """
    import asyncio

    violations = asyncio.run(rule_non_standard_proxy.check(proxy_state, "", None))
    return violations[0] if violations else None
