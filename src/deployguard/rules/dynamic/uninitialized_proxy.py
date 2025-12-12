"""UNINITIALIZED_PROXY: Uninitialized Proxy rule."""

from deployguard.models.dynamic import ProxyState
from deployguard.models.rules import Rule, RuleCategory, RuleViolation, Severity
from deployguard.rules.base import DynamicRule

RULE_UNINITIALIZED_PROXY = Rule(
    rule_id="UNINITIALIZED_PROXY",
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


class UninitializedProxyRule(DynamicRule):
    """UNINITIALIZED_PROXY: Check for uninitialized proxy.

    Detects proxies where the implementation slot is empty (zero address),
    indicating the proxy was never initialized.
    """

    async def check(
        self,
        proxy_state: ProxyState,
        expected_impl: str,
        expected_admin: str | None = None,
    ) -> list[RuleViolation]:
        """Check if proxy is uninitialized.

        Args:
            proxy_state: Current proxy state from chain
            expected_impl: Expected implementation address (unused)
            expected_admin: Expected admin address (unused)

        Returns:
            List containing violation if proxy is uninitialized, empty otherwise
        """
        violations = []
        impl_value = proxy_state.implementation_slot.value
        zero_slot = "0x" + "0" * 64

        if impl_value == zero_slot:
            violations.append(
                RuleViolation(
                    rule=self.rule,
                    severity=self.rule.severity,
                    message="Proxy implementation slot is empty (uninitialized)",
                    recommendation=self.rule.remediation,
                    storage_data=proxy_state.implementation_slot,
                    context={
                        "proxy_address": str(proxy_state.proxy_address),
                        "slot_value": str(impl_value),
                        "block_number": proxy_state.implementation_slot.block_number,
                    },
                )
            )

        return violations


# Instantiate rule for registration
rule_uninitialized_proxy = UninitializedProxyRule(RULE_UNINITIALIZED_PROXY)


# Backward compatibility function (deprecated)
def check_uninitialized_proxy(proxy_state: ProxyState) -> RuleViolation | None:
    """Check if proxy is uninitialized.

    .. deprecated::
        Use UninitializedProxyRule class instead.

    Args:
        proxy_state: Current proxy state from chain

    Returns:
        RuleViolation if proxy is uninitialized, None otherwise
    """
    import asyncio

    violations = asyncio.run(rule_uninitialized_proxy.check(proxy_state, "", None))
    return violations[0] if violations else None
