"""UUPS_UPGRADE_OVERRIDE: UUPS Override of upgradeToAndCall.

Detects UUPS implementations that override upgradeToAndCall without preserving
the upgrade functionality.
"""


from deployguard.models.rules import Rule, RuleCategory, RuleViolation, Severity
from deployguard.models.static import ProxyType, ScriptAnalysis
from deployguard.rules.base import StaticRule


class UUPSUpgradeToAndCallOverrideRule(StaticRule):
    """Detect unsafe overrides of upgradeToAndCall in UUPS implementations.

    If upgradeToAndCall is overridden, it must preserve the upgrade functionality.
    Overriding without calling super.upgradeToAndCall() or without proper implementation
    can break the upgrade mechanism.

    This is a simplified check that warns when UUPS proxies are detected.
    Full verification requires analyzing if upgradeToAndCall is overridden in the
    implementation contract.
    """

    def check(self, analysis: ScriptAnalysis) -> list[RuleViolation]:
        """Check for UUPS proxies and warn about upgradeToAndCall.

        Args:
            analysis: Parsed deployment script

        Returns:
            List of violations (warnings for UUPS deployments)
        """
        violations = []

        # Find UUPS proxy deployments
        uups_deployments = [
            d for d in analysis.proxy_deployments if d.proxy_type == ProxyType.UUPS_UPGRADEABLE
        ]

        for deployment in uups_deployments:
            message = (
                f"UUPS proxy detected. If your implementation overrides upgradeToAndCall(), "
                f"ensure it calls super.upgradeToAndCall() to preserve upgrade functionality."
            )

            violations.append(
                RuleViolation(
                    rule=self.rule,
                    severity=self.rule.severity,
                    message=message,
                    recommendation=(
                        f"If you override upgradeToAndCall(), always call super:\n\n"
                        f"  function upgradeToAndCall(\n"
                        f"      address newImplementation,\n"
                        f"      bytes memory data\n"
                        f"  ) public payable override onlyProxy {{\n"
                        f"      // Call parent implementation\n"
                        f"      super.upgradeToAndCall(newImplementation, data);\n\n"
                        f"      // Your additional logic (if needed)\n"
                        f"  }}\n\n"
                        f"Best practice: Don't override upgradeToAndCall() unless absolutely necessary.\n"
                        f"The default implementation is secure and well-tested."
                    ),
                    location=deployment.location,
                    context={
                        "proxy_type": deployment.proxy_type.value,
                        "implementation": deployment.implementation_arg,
                        "check_type": "uups_upgrade_to_and_call",
                    },
                )
            )

        return violations


# Create rule instance
RULE_UUPS_UPGRADE_OVERRIDE = Rule(
    rule_id="UUPS_UPGRADE_OVERRIDE",
    name="UUPS Override of upgradeToAndCall",
    description="UUPS implementation overrides upgradeToAndCall, verify it preserves functionality",
    severity=Severity.HIGH,
    category=RuleCategory.SECURITY,
    references=[
        "https://rareskills.io/post/uups-proxy",
    ],
    remediation="Ensure upgradeToAndCall override calls super.upgradeToAndCall()",
)

rule_uups_upgrade_override = UUPSUpgradeToAndCallOverrideRule(RULE_UUPS_UPGRADE_OVERRIDE)
