"""UUPS_NO_DISABLE_INIT: UUPS Missing _disableInitializers in Constructor.

Detects UUPS implementations that don't call _disableInitializers() in their
constructor, leaving them vulnerable to direct initialization attacks.
"""

import re


from deployguard.models.rules import Rule, RuleCategory, RuleViolation, Severity
from deployguard.models.static import ProxyType, ScriptAnalysis
from deployguard.rules.base import StaticRule


class UUPSMissingDisableInitializersRule(StaticRule):
    """Detect UUPS implementations without _disableInitializers() in constructor.

    UUPS implementation contracts should call _disableInitializers() in their
    constructor to prevent the implementation contract itself from being initialized.
    This prevents the "UUPS uninitialized logic" attack where an attacker could
    initialize the implementation contract directly.

    This is a simplified check that warns when UUPS proxies are detected.
    Full verification requires analyzing the implementation contract's constructor.
    """

    def check(self, analysis: ScriptAnalysis) -> list[RuleViolation]:
        """Check for UUPS proxies and warn about _disableInitializers.

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
                f"UUPS proxy detected. Ensure the implementation contract constructor "
                f"calls _disableInitializers() to prevent direct initialization attacks "
                f"on the implementation contract."
            )

            violations.append(
                RuleViolation(
                    rule=self.rule,
                    severity=self.rule.severity,
                    message=message,
                    recommendation=(
                        f"Add _disableInitializers() to implementation contract constructor:\n\n"
                        f"  contract MyContract is UUPSUpgradeable {{\n"
                        f"      /// @custom:oz-upgrades-unsafe-allow constructor\n"
                        f"      constructor() {{\n"
                        f"          _disableInitializers();\n"
                        f"      }}\n\n"
                        f"      function initialize() public initializer {{\n"
                        f"          __UUPSUpgradeable_init();\n"
                        f"          // Your initialization logic\n"
                        f"      }}\n"
                        f"  }}\n\n"
                        f"This prevents attackers from initializing the implementation contract directly.\n\n"
                        f"See: https://docs.openzeppelin.com/upgrades-plugins/1.x/writing-upgradeable#initializing_the_implementation_contract"
                    ),
                    location=deployment.location,
                    context={
                        "proxy_type": deployment.proxy_type.value,
                        "implementation": deployment.implementation_arg,
                        "check_type": "uups_disable_initializers",
                    },
                )
            )

        return violations


# Create rule instance
RULE_UUPS_NO_DISABLE_INIT = Rule(
    rule_id="UUPS_NO_DISABLE_INIT",
    name="UUPS Missing _disableInitializers in Constructor",
    description="UUPS implementation constructor must call _disableInitializers()",
    severity=Severity.HIGH,
    category=RuleCategory.SECURITY,
    references=[
        "https://rareskills.io/post/uups-proxy",#initializing_the_implementation_contrrac:
    ],
    remediation="Call _disableInitializers() in implementation contract constructor",
)

rule_uups_no_disable_init = UUPSMissingDisableInitializersRule(RULE_UUPS_NO_DISABLE_INIT)
