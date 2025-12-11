"""DG-002: Separated Deploy and Initialize.

Detects when proxy deployment and initialization occur in separate transactions,
which also creates a front-running vulnerability window.
"""


from deployguard.models.rules import Rule, RuleCategory, RuleViolation, Severity
from deployguard.models.static import ScriptAnalysis
from deployguard.rules.base import StaticRule


class SeparatedInitRule(StaticRule):
    """Detect when deploy and initialize are in separate transactions.

    This rule checks if a proxy deployment and its subsequent initialization
    occur across transaction boundaries (vm.broadcast, vm.startBroadcast, etc.),
    which means they will be sent as separate transactions on-chain.

    Even if initialization is called immediately after deployment in the script,
    if they're in different tx boundaries, an attacker can front-run the
    initialization transaction.
    """

    def check(self, analysis: ScriptAnalysis) -> list[RuleViolation]:
        """Check for separated deployment and initialization.

        Args:
            analysis: Parsed deployment script

        Returns:
            List of violations (one per non-atomic deployment)
        """
        violations = []

        for deployment in analysis.proxy_deployments:
            # Check if deployment is marked as non-atomic (separate tx)
            if not deployment.is_atomic:
                message = (
                    f"{deployment.proxy_type.value} deployment and initialization "
                    f"occur in separate transactions. This creates a front-running "
                    f"vulnerability where an attacker can initialize the proxy between "
                    f"the deployment and initialization transactions."
                )

                violations.append(
                    RuleViolation(
                        rule=self.rule,
                        severity=self.rule.severity,
                        message=message,
                        recommendation=(
                            f"Combine deployment and initialization in a single transaction:\n\n"
                            f"  vm.startBroadcast();\n"
                            f"  // Both operations within same broadcast scope\n"
                            f"  bytes memory data = abi.encodeCall({{Contract}}.initialize, ({{args}}));\n"
                            f"  {deployment.proxy_type.value} proxy = new {deployment.proxy_type.value}(impl, data);\n"
                            f"  vm.stopBroadcast();\n\n"
                            f"Avoid stopping broadcast between deployment and initialization."
                        ),
                        location=deployment.location,
                        context={
                            "proxy_type": deployment.proxy_type.value,
                            "tx_boundary_before": (
                                str(deployment.tx_boundary_before)
                                if deployment.tx_boundary_before
                                else None
                            ),
                            "tx_boundary_after": (
                                str(deployment.tx_boundary_after)
                                if deployment.tx_boundary_after
                                else None
                            ),
                        },
                    )
                )

        return violations


# Create rule instance
RULE_DG_002 = Rule(
    rule_id="DG-002",
    name="Separated Deploy and Initialize",
    description="Proxy deployment and initialization in separate transactions",
    severity=Severity.HIGH,
    category=RuleCategory.PROXY,
    references=[
        "https://book.getfoundry.sh/tutorials/best-practices#use-startbroadcast-and-stopbroadcast",
    ],
    remediation="Combine deployment and initialization in single transaction",
)

rule_dg002 = SeparatedInitRule(RULE_DG_002)
