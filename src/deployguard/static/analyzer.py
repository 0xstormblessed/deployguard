"""Static analyzer for deployment scripts.

This module provides the main entry point for static analysis of
Foundry deployment scripts.
"""

from __future__ import annotations

import re
from pathlib import Path

from deployguard.config import DeployGuardConfig
from deployguard.models.rules import Rule, RuleCategory, RuleViolation, Severity
from deployguard.models.static import (
    BoundaryType,
    ProxyDeployment,
    ScriptAnalysis,
    TransactionBoundary,
)
from deployguard.static.parsers.foundry import FoundryScriptParser

# Built-in static rules
RULE_DG_001 = Rule(
    rule_id="DG-001",
    name="Non-Atomic Proxy Initialization",
    description="Proxy deployed with empty initialization data, requiring a separate transaction to initialize.",
    severity=Severity.CRITICAL,
    category=RuleCategory.PROXY,
    references=["https://github.com/example/cpimp-vulnerability"],
    remediation="Pass initialization data to the proxy constructor using abi.encodeCall() or abi.encodeWithSelector().",
)

RULE_DG_002 = Rule(
    rule_id="DG-002",
    name="Separated Deploy and Initialize",
    description="Proxy deployment and initialization occur in separate transactions.",
    severity=Severity.HIGH,
    category=RuleCategory.PROXY,
    references=[],
    remediation="Ensure proxy deployment and initialization occur within the same vm.broadcast scope.",
)

RULE_DG_003 = Rule(
    rule_id="DG-003",
    name="Hardcoded Implementation Address",
    description="Implementation address is hardcoded rather than deployed in the same script.",
    severity=Severity.MEDIUM,
    category=RuleCategory.PROXY,
    references=[],
    remediation="Deploy the implementation contract in the same script or use environment variables.",
)

RULE_DG_004 = Rule(
    rule_id="DG-004",
    name="Missing Implementation Validation",
    description="Implementation address is used without validation (e.g., checking it's a contract).",
    severity=Severity.LOW,
    category=RuleCategory.PROXY,
    references=[],
    remediation="Add validation: require(impl.code.length > 0) before using the implementation address.",
)


class StaticAnalyzer:
    """Static analyzer for deployment scripts.

    Parses deployment scripts and runs static analysis rules to detect
    potential vulnerabilities and issues.
    """

    def __init__(self, config: DeployGuardConfig | None = None) -> None:
        """Initialize the static analyzer.

        Args:
            config: Optional configuration
        """
        self.config = config
        self.parser = FoundryScriptParser()

    def analyze_file(self, file_path: Path | str) -> ScriptAnalysis:
        """Analyze a deployment script file.

        Args:
            file_path: Path to the deployment script

        Returns:
            ScriptAnalysis with detected patterns
        """
        path = Path(file_path) if isinstance(file_path, str) else file_path

        if not path.exists():
            raise FileNotFoundError(f"Script file not found: {path}")

        return self.parser.parse_file(path)

    def analyze_source(self, source: str, file_path: str = "<source>") -> ScriptAnalysis:
        """Analyze deployment script source code.

        Args:
            source: Solidity source code
            file_path: Path for error reporting

        Returns:
            ScriptAnalysis with detected patterns
        """
        return self.parser.parse_source(source, file_path)

    def run_rules(self, analysis: ScriptAnalysis) -> list[RuleViolation]:
        """Run all static analysis rules against parsed script.

        Args:
            analysis: Parsed script analysis

        Returns:
            List of rule violations found
        """
        violations: list[RuleViolation] = []

        for deployment in analysis.proxy_deployments:
            # DG-001: Non-Atomic Proxy Initialization
            violation = self._check_non_atomic_init(deployment)
            if violation:
                violations.append(violation)

            # DG-002: Separated Deploy and Initialize
            violation = self._check_separated_init(deployment, analysis)
            if violation:
                violations.append(violation)

            # DG-003: Hardcoded Implementation Address
            violation = self._check_hardcoded_impl(deployment, analysis)
            if violation:
                violations.append(violation)

            # DG-004: Missing Implementation Validation
            violation = self._check_impl_validation(deployment, analysis)
            if violation:
                violations.append(violation)

        return violations

    def _check_non_atomic_init(self, deployment: ProxyDeployment) -> RuleViolation | None:
        """Check for non-atomic proxy initialization (DG-001).

        Args:
            deployment: Proxy deployment to check

        Returns:
            RuleViolation if non-atomic init detected
        """
        if deployment.has_empty_init:
            return RuleViolation(
                rule=RULE_DG_001,
                severity=Severity.CRITICAL,
                message=f"Proxy deployed with empty initialization data at line {deployment.location.line_number}",
                recommendation=(
                    f"Pass initialization data to the proxy constructor:\n"
                    f"  new {deployment.proxy_type.value}(address(impl), "
                    f"abi.encodeCall(Implementation.initialize, (args)))"
                ),
                location=deployment.location,
                context={
                    "proxy_type": deployment.proxy_type.value,
                    "init_data_arg": deployment.init_data_arg,
                },
            )
        return None

    def _check_separated_init(
        self,
        deployment: ProxyDeployment,
        analysis: ScriptAnalysis,
    ) -> RuleViolation | None:
        """Check for separated deployment and initialization (DG-002).

        This checks if the proxy deployment and its initialization call
        occur in different transaction scopes.

        Args:
            deployment: Proxy deployment to check
            analysis: Full script analysis with boundaries and function calls

        Returns:
            RuleViolation if separated init detected
        """
        if not deployment.has_empty_init:
            return None

        # Find transaction scope for deployment
        deploy_line = deployment.location.line_number
        deploy_scope = self._find_tx_scope(deploy_line, analysis.tx_boundaries)

        # If we have a proxy variable, look for initialize() calls on it
        if deployment.proxy_variable:
            # Find initialize() calls on this proxy variable
            init_calls = [
                call
                for call in analysis.function_calls
                if call.receiver == deployment.proxy_variable and call.function_name == "initialize"
            ]

            # Check if any init call is in a different scope
            for init_call in init_calls:
                init_scope = self._find_tx_scope(
                    init_call.location.line_number, analysis.tx_boundaries
                )

                # If scopes differ, flag it
                if deploy_scope != init_scope:
                    return RuleViolation(
                        rule=RULE_DG_002,
                        severity=Severity.HIGH,
                        message=(
                            f"Proxy deployment at line {deploy_line} and initialization "
                            f"at line {init_call.location.line_number} are in different transaction scopes"
                        ),
                        recommendation=(
                            "Ensure proxy deployment and initialization occur within "
                            "the same vm.broadcast scope, or use atomic initialization "
                            "by passing init data to the proxy constructor."
                        ),
                        location=deployment.location,
                        context={
                            "deploy_line": deploy_line,
                            "init_line": init_call.location.line_number,
                            "deploy_scope": deploy_scope,
                            "init_scope": init_scope,
                        },
                    )

        # If no proxy variable or no init calls found, fall back to heuristic
        # Check if multiple broadcast scopes exist
        start_broadcasts = [
            b for b in analysis.tx_boundaries if b.boundary_type == BoundaryType.VM_START_BROADCAST
        ]
        single_broadcasts = [
            b for b in analysis.tx_boundaries if b.boundary_type == BoundaryType.VM_BROADCAST
        ]

        if len(start_broadcasts) > 1 or len(single_broadcasts) > 1:
            return RuleViolation(
                rule=RULE_DG_002,
                severity=Severity.HIGH,
                message=(
                    f"Proxy deployment at line {deploy_line} has empty init data "
                    f"and script has multiple transaction scopes"
                ),
                recommendation=(
                    "Ensure proxy deployment and initialization occur within "
                    "the same vm.broadcast scope, or use atomic initialization "
                    "by passing init data to the proxy constructor."
                ),
                location=deployment.location,
                context={
                    "deploy_line": deploy_line,
                    "num_broadcast_scopes": len(start_broadcasts) + len(single_broadcasts),
                },
            )

        return None

    def _find_tx_scope(
        self, line_number: int, boundaries: list[TransactionBoundary]
    ) -> tuple[int, int] | None:
        """Find which transaction scope a line belongs to.

        Args:
            line_number: Line to check
            boundaries: Transaction boundaries

        Returns:
            Tuple of (scope_start, scope_end) or None if not in any scope
        """
        # Check vm.startBroadcast/stopBroadcast scopes first
        for boundary in boundaries:
            if boundary.boundary_type == BoundaryType.VM_START_BROADCAST:
                scope_start = boundary.scope_start
                scope_end = boundary.scope_end

                if scope_end and scope_start <= line_number <= scope_end:
                    return (scope_start, scope_end)

        # Check vm.broadcast() single-line scopes
        # vm.broadcast() affects the next statement only
        for boundary in boundaries:
            if boundary.boundary_type == BoundaryType.VM_BROADCAST:
                # Assume next line is in scope (simple heuristic)
                if boundary.scope_start + 1 == line_number:
                    return (boundary.scope_start, boundary.scope_start + 1)

        return None

    def _check_hardcoded_impl(
        self, deployment: ProxyDeployment, analysis: ScriptAnalysis
    ) -> RuleViolation | None:
        """Check for hardcoded implementation address (DG-003).

        Args:
            deployment: Proxy deployment to check
            analysis: Full script analysis

        Returns:
            RuleViolation if hardcoded impl address detected
        """
        impl_arg = deployment.implementation_arg

        # Check if it's a literal address (0x followed by 40 hex chars)
        if re.match(r"^0x[a-fA-F0-9]{40}$", impl_arg.strip()):
            return RuleViolation(
                rule=RULE_DG_003,
                severity=Severity.MEDIUM,
                message=f"Implementation address is hardcoded: {impl_arg}",
                recommendation=(
                    "Deploy the implementation contract in the same script:\n"
                    "  Implementation impl = new Implementation();\n"
                    "  new Proxy(address(impl), initData);\n"
                    "Or use an environment variable:\n"
                    '  address impl = vm.envAddress("IMPL_ADDRESS");'
                ),
                location=deployment.location,
                context={"hardcoded_address": impl_arg},
            )

        # Check if variable is assigned a hardcoded value
        # Strip address() wrapper if present
        var_name = impl_arg.strip()
        if var_name.startswith("address(") and var_name.endswith(")"):
            var_name = var_name[8:-1].strip()

        if var_name in analysis.implementation_variables:
            var_info = analysis.implementation_variables[var_name]
            if var_info.is_hardcoded:
                return RuleViolation(
                    rule=RULE_DG_003,
                    severity=Severity.MEDIUM,
                    message=f"Implementation address variable '{var_name}' contains hardcoded value",
                    recommendation=(
                        "Deploy the implementation contract in the same script "
                        "or use an environment variable."
                    ),
                    location=deployment.location,
                    context={
                        "variable_name": var_name,
                        "assigned_value": var_info.assigned_value,
                    },
                )

        return None

    def _check_impl_validation(
        self, deployment: ProxyDeployment, analysis: ScriptAnalysis
    ) -> RuleViolation | None:
        """Check for missing implementation validation (DG-004).

        Args:
            deployment: Proxy deployment to check
            analysis: Full script analysis

        Returns:
            RuleViolation if no validation detected
        """
        impl_arg = deployment.implementation_arg

        # Strip address() wrapper if present
        var_name = impl_arg.strip()
        if var_name.startswith("address(") and var_name.endswith(")"):
            var_name = var_name[8:-1].strip()

        # Check if variable has validation
        if var_name in analysis.implementation_variables:
            var_info = analysis.implementation_variables[var_name]
            if var_info.is_validated:
                return None

        # Check for new Contract() pattern - this is implicitly validated
        if var_name.startswith("new ") or "new " in impl_arg:
            return None

        # If it's a freshly deployed contract (variable assigned with new),
        # no validation needed
        if var_name in analysis.implementation_variables:
            var_info = analysis.implementation_variables[var_name]
            if var_info.assigned_value and "new " in var_info.assigned_value:
                return None

        # TODO: Look for validation patterns before the deployment
        # For now, flag if not a new deployment
        return RuleViolation(
            rule=RULE_DG_004,
            severity=Severity.LOW,
            message=f"Implementation address '{impl_arg}' used without validation",
            recommendation=(
                "Add validation before using the implementation address:\n"
                f'  require({var_name}.code.length > 0, "Implementation not a contract");\n'
                f'  require({var_name} != address(0), "Implementation cannot be zero");'
            ),
            location=deployment.location,
            context={"implementation_arg": impl_arg},
        )


def analyze_script(file_path: str, config: DeployGuardConfig | None = None) -> ScriptAnalysis:
    """Analyze a Foundry deployment script for vulnerabilities.

    Args:
        file_path: Path to deployment script (*.s.sol)
        config: Optional configuration

    Returns:
        ScriptAnalysis with detected patterns and issues

    Raises:
        FileNotFoundError: If script file doesn't exist
        ParseError: If script cannot be parsed
    """
    analyzer = StaticAnalyzer(config)
    return analyzer.analyze_file(file_path)


def run_static_rules(
    analysis: ScriptAnalysis, rules: list[Rule] | None = None
) -> list[RuleViolation]:
    """Run static analysis rules against parsed script.

    Args:
        analysis: Parsed script analysis
        rules: List of rules to execute (uses all built-in rules if None)

    Returns:
        List of rule violations found
    """
    analyzer = StaticAnalyzer()
    return analyzer.run_rules(analysis)
