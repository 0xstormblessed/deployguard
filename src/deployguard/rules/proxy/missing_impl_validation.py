"""MISSING_IMPL_VALIDATION: Missing Implementation Validation.

Detects when implementation addresses are used without validating that
they contain actual contract bytecode.
"""

import re


from deployguard.models.rules import Rule, RuleCategory, RuleViolation, Severity
from deployguard.models.static import ScriptAnalysis
from deployguard.rules.base import StaticRule


class MissingValidationRule(StaticRule):
    """Detect missing implementation address validation.

    When using an implementation address from an external source (env var,
    config file, hardcoded), it's important to validate that:
    1. The address is not zero
    2. The address contains contract bytecode (.code.length > 0)

    This prevents deploying proxies that point to:
    - Empty addresses (zero address)
    - EOAs (externally owned accounts)
    - Addresses without deployed contracts

    Note: This rule only flags missing validation for addresses from
    external sources. If the implementation is deployed in the same script
    (e.g., `new MyContract()`), validation is not necessary.
    """

    # Patterns that indicate validation checks
    VALIDATION_PATTERNS = [
        re.compile(r"\.code\.length\s*>\s*0"),
        re.compile(r"isContract\s*\("),
        re.compile(r"require\s*\([^)]*!=\s*address\s*\(\s*0\s*\)"),
        re.compile(r"require\s*\([^)]*>\s*address\s*\(\s*0\s*\)"),
        re.compile(r"if\s*\([^)]*==\s*address\s*\(\s*0\s*\)\s*\)\s*revert"),
    ]

    def check(self, analysis: ScriptAnalysis) -> list[RuleViolation]:
        """Check for missing implementation validation.

        Args:
            analysis: Parsed deployment script

        Returns:
            List of violations (one per unvalidated external address)
        """
        violations = []

        for deployment in analysis.proxy_deployments:
            impl_arg = deployment.implementation_arg.strip()

            # Skip if implementation is deployed in same script (e.g., "address(impl)")
            # These don't need validation since we just deployed them
            if self._is_same_script_deployment(impl_arg):
                continue

            # Check if this is a variable that might be from external source
            if impl_arg in analysis.implementation_variables:
                var_info = analysis.implementation_variables[impl_arg]

                # If variable is not validated, flag it
                if not var_info.is_validated:
                    message = (
                        f"Implementation address '{impl_arg}' is used without validation. "
                        f"The address may be zero or may not contain contract bytecode, "
                        f"leading to a non-functional proxy."
                    )

                    violations.append(
                        RuleViolation(
                            rule=self.rule,
                            severity=self.rule.severity,
                            message=message,
                            recommendation=(
                                f"Add validation before using the implementation address:\n\n"
                                f"  // Load implementation address\n"
                                f"  address impl = vm.envAddress(\"IMPLEMENTATION\");\n\n"
                                f"  // Validate it's not zero and has code\n"
                                f"  require(impl != address(0), \"Zero address\");\n"
                                f"  require(impl.code.length > 0, \"Not a contract\");\n\n"
                                f"  // Now safe to use\n"
                                f"  proxy = new ERC1967Proxy(impl, data);"
                            ),
                            location=var_info.assignment_location,
                            context={
                                "variable": impl_arg,
                                "proxy_type": deployment.proxy_type.value,
                                "is_hardcoded": var_info.is_hardcoded,
                            },
                        )
                    )

        return violations

    def _is_same_script_deployment(self, impl_arg: str) -> bool:
        """Check if implementation is deployed in the same script.

        Args:
            impl_arg: The implementation argument

        Returns:
            True if it's a same-script deployment (e.g., "address(impl)")
        """
        # Patterns that indicate same-script deployment
        same_script_patterns = [
            r"address\s*\(",  # address(impl)
            r"new\s+\w+",  # new MyContract()
        ]

        return any(re.search(pattern, impl_arg) for pattern in same_script_patterns)


# Create rule instance
RULE_MISSING_IMPL_VALIDATION = Rule(
    rule_id="MISSING_IMPL_VALIDATION",
    name="Missing Implementation Validation",
    description="Implementation address used without validation",
    severity=Severity.LOW,
    category=RuleCategory.PROXY,
    references=[
        "https://rareskills.io/post/solidity-code-length",
    ],
    remediation="Add require(impl.code.length > 0) before proxy deployment",
)

rule_missing_impl_validation = MissingValidationRule(RULE_MISSING_IMPL_VALIDATION)
