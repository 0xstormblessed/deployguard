"""DG-001: Non-Atomic Proxy Initialization.

Detects proxy contracts deployed with empty initialization data, which creates
a window for front-running attacks where an attacker can initialize the proxy
before the legitimate owner.
"""

from deployguard.models.rules import Rule, RuleCategory, RuleViolation, Severity
from deployguard.models.static import ScriptAnalysis
from deployguard.rules.base import StaticRule


class NonAtomicInitRule(StaticRule):
    """Detect proxies deployed without atomic initialization.

    This rule checks for proxy deployments where the initialization data
    parameter is empty ("", "0x", or bytes("")), requiring a separate
    transaction to initialize the proxy.

    The CPIMP (Constructor Proxy Initialization Mitigation Pattern) attack
    occurs when:
    1. Proxy is deployed with empty init data
    2. Attacker monitors mempool for proxy deployment
    3. Attacker front-runs the initialization transaction
    4. Attacker gains control of the proxy

    Prevention: Pass encoded initialization data directly to the proxy
    constructor to make deployment atomic.
    """

    def check(self, analysis: ScriptAnalysis) -> list[RuleViolation]:
        """Check for non-atomic proxy initialization.

        Args:
            analysis: Parsed deployment script

        Returns:
            List of violations (one per proxy with empty init data)
        """
        violations = []

        for deployment in analysis.proxy_deployments:
            if deployment.has_empty_init:
                # Build detailed message
                message = (
                    f"{deployment.proxy_type.value} deployed with empty initialization "
                    f"data ('{deployment.init_data_arg}'). This creates a window for "
                    f"front-running attacks where an attacker can initialize the proxy "
                    f"before you."
                )

                violations.append(
                    RuleViolation(
                        rule=self.rule,
                        severity=self.rule.severity,
                        message=message,
                        recommendation=(
                            f"Pass initialization data to the proxy constructor to make deployment atomic:\n\n"
                            f"  // Encode the initialization call\n"
                            f"  bytes memory data = abi.encodeCall({{Contract}}.initialize, ({{args}}));\n\n"
                            f"  // Deploy proxy with initialization data\n"
                            f"  {deployment.proxy_type.value} proxy = new {deployment.proxy_type.value}(\n"
                            f"      address(impl),\n"
                            f"      data  // NOT empty string\n"
                            f"  );\n\n"
                            f"See: https://blog.openzeppelin.com/protect-your-users-with-smart-contract-timelocks"
                        ),
                        location=deployment.location,
                        context={
                            "proxy_type": deployment.proxy_type.value,
                            "init_data_arg": deployment.init_data_arg,
                            "implementation_arg": deployment.implementation_arg,
                            "proxy_variable": deployment.proxy_variable,
                        },
                    )
                )

        return violations


# Create rule instance
RULE_DG_001 = Rule(
    rule_id="DG-001",
    name="Non-Atomic Proxy Initialization",
    description="Proxy deployed with empty initialization data",
    severity=Severity.CRITICAL,
    category=RuleCategory.PROXY,
    references=[
        "https://docs.openzeppelin.com/upgrades-plugins/1.x/proxies",
        "https://blog.openzeppelin.com/proxy-patterns",
        "https://blog.openzeppelin.com/protect-your-users-with-smart-contract-timelocks",
    ],
    remediation="Pass encoded initialization data to proxy constructor",
)

# Instantiate rule (will be registered when module is imported)
rule_dg001 = NonAtomicInitRule(RULE_DG_001)
