"""HARDCODED_IMPL: Hardcoded Implementation Address.

Detects when implementation addresses are hardcoded in deployment scripts,
which can lead to using wrong or malicious implementations.
"""

import re


from deployguard.models.rules import Rule, RuleCategory, RuleViolation, Severity
from deployguard.models.static import ScriptAnalysis
from deployguard.rules.base import StaticRule


class HardcodedImplRule(StaticRule):
    """Detect hardcoded implementation addresses.

    Hardcoding implementation addresses in deployment scripts is risky because:
    1. The address may be from a different network (e.g., mainnet addr on testnet)
    2. The address may point to an outdated or malicious contract
    3. No verification that bytecode exists at that address
    4. Difficult to audit and maintain

    Best practice: Deploy the implementation in the same script or load from
    a verified environment variable/config file.
    """

    ADDRESS_PATTERN = re.compile(r"^0x[a-fA-F0-9]{40}$")

    def check(self, analysis: ScriptAnalysis) -> list[RuleViolation]:
        """Check for hardcoded implementation addresses.

        Args:
            analysis: Parsed deployment script

        Returns:
            List of violations (one per hardcoded address)
        """
        violations = []

        for deployment in analysis.proxy_deployments:
            impl_arg = deployment.implementation_arg.strip()

            # Check if implementation is a literal address
            if self._is_literal_address(impl_arg):
                violations.append(
                    self._create_violation(
                        deployment, impl_arg, is_literal=True, analysis=analysis
                    )
                )
                continue

            # Check if implementation is a variable with hardcoded value
            if impl_arg in analysis.implementation_variables:
                var_info = analysis.implementation_variables[impl_arg]
                if var_info.is_hardcoded:
                    violations.append(
                        self._create_violation(
                            deployment,
                            impl_arg,
                            is_literal=False,
                            var_location=var_info.assignment_location,
                            var_value=var_info.assigned_value,
                            analysis=analysis,
                        )
                    )

        return violations

    def _is_literal_address(self, value: str) -> bool:
        """Check if value is a literal Ethereum address."""
        return bool(self.ADDRESS_PATTERN.match(value))

    def _create_violation(
        self,
        deployment,
        impl_arg: str,
        is_literal: bool,
        analysis: ScriptAnalysis,
        var_location=None,
        var_value=None,
    ) -> RuleViolation:
        """Create a violation for a hardcoded implementation."""
        if is_literal:
            message = (
                f"Implementation address is hardcoded as literal: {impl_arg}. "
                f"This may point to wrong contract (different network) or lack validation."
            )
            location = deployment.location
        else:
            message = (
                f"Variable '{impl_arg}' contains hardcoded address: {var_value}. "
                f"Consider deploying implementation in same script or using environment variables."
            )
            location = var_location or deployment.location

        return RuleViolation(
            rule=self.rule,
            severity=self.rule.severity,
            message=message,
            recommendation=(
                f"Best practices for implementation addresses:\n\n"
                f"  1. Deploy implementation in same script:\n"
                f"     MyContract impl = new MyContract();\n"
                f"     proxy = new ERC1967Proxy(address(impl), data);\n\n"
                f"  2. Load from environment variable:\n"
                f"     address impl = vm.envAddress(\"IMPLEMENTATION_ADDRESS\");\n\n"
                f"  3. Load from config file with verification:\n"
                f"     require(impl.code.length > 0, \"Invalid implementation\");"
            ),
            location=location,
            context={
                "proxy_type": deployment.proxy_type.value,
                "implementation_arg": impl_arg,
                "is_literal": is_literal,
                "value": impl_arg if is_literal else var_value,
            },
        )


# Create rule instance
RULE_HARDCODED_IMPL = Rule(
    rule_id="HARDCODED_IMPL",
    name="Hardcoded Implementation Address",
    description="Implementation address is hardcoded in script",
    severity=Severity.MEDIUM,
    category=RuleCategory.PROXY,
    references=[
        "https://book.getfoundry.sh/tutorials/best-practices#dont-use-hardcoded-addresses",
    ],
    remediation="Deploy implementation in same script or use environment variables",
)

rule_hardcoded_impl = HardcodedImplRule(RULE_HARDCODED_IMPL)
