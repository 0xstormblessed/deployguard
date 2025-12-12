"""UUPS_UNSAFE_OPCODE: UUPS Implementation Uses Delegatecall or Selfdestruct.

Detects UUPS implementation contracts that contain delegatecall or selfdestruct,
which can be used to bypass proxy security mechanisms.
"""


from deployguard.models.rules import Rule, RuleCategory, RuleViolation, Severity
from deployguard.models.static import ProxyType, ScriptAnalysis
from deployguard.rules.base import StaticRule


class UUPSDelegatecallSelfdestructRule(StaticRule):
    """Detect delegatecall or selfdestruct in UUPS implementation contracts.

    UUPS implementation contracts should not contain delegatecall or selfdestruct
    as these can be used to bypass proxy security mechanisms or destroy the contract:

    - delegatecall: Can be used to bypass proxy security by delegating to malicious code
    - selfdestruct: Can destroy the implementation contract, breaking all proxies

    This is a warning-level check that alerts developers when UUPS is used.
    Full verification requires bytecode or AST analysis of the implementation.
    """

    def check(self, analysis: ScriptAnalysis) -> list[RuleViolation]:
        """Check for UUPS proxies and warn about delegatecall/selfdestruct.

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
                f"UUPS proxy detected. CRITICAL: Ensure the implementation contract "
                f"does NOT contain delegatecall or selfdestruct opcodes, as these can "
                f"be used to bypass security or destroy the proxy."
            )

            violations.append(
                RuleViolation(
                    rule=self.rule,
                    severity=self.rule.severity,
                    message=message,
                    recommendation=(
                        f"Verify your UUPS implementation contract does NOT contain:\n\n"
                        f"  ❌ delegatecall:\n"
                        f"     - address.delegatecall()\n"
                        f"     - assembly {{ delegatecall(...) }}\n\n"
                        f"  ❌ selfdestruct:\n"
                        f"     - selfdestruct(address)\n"
                        f"     - assembly {{ selfdestruct(...) }}\n\n"
                        f"These opcodes can:\n"
                        f"  - Allow attackers to execute arbitrary code via delegatecall\n"
                        f"  - Destroy the implementation, breaking all proxies\n\n"
                        f"If you absolutely need delegatecall (e.g., for specific proxy patterns),\n"
                        f"ensure it's protected with strict access controls and validate the target.\n\n"
                        f"Recommended: Use OpenZeppelin's audited UUPS implementation without modifications."
                    ),
                    location=deployment.location,
                    context={
                        "proxy_type": deployment.proxy_type.value,
                        "implementation": deployment.implementation_arg,
                        "check_type": "uups_delegatecall_selfdestruct",
                        "note": "Manual review required - check implementation contract bytecode",
                    },
                )
            )

        return violations


# Create rule instance
RULE_UUPS_UNSAFE_OPCODE = Rule(
    rule_id="UUPS_UNSAFE_OPCODE",
    name="UUPS Implementation Uses Delegatecall or Selfdestruct",
    description="UUPS implementation contains dangerous opcodes (delegatecall/selfdestruct)",
    severity=Severity.CRITICAL,
    category=RuleCategory.SECURITY,
    references=[
        "https://rareskills.io/post/uups-proxy",
    ],
    remediation="Remove delegatecall and selfdestruct from UUPS implementation contract",
)

rule_uups_unsafe_opcode = UUPSDelegatecallSelfdestructRule(RULE_UUPS_UNSAFE_OPCODE)
