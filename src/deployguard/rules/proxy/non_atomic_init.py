"""NON_ATOMIC_INIT: Non-Atomic Proxy Initialization.

Detects proxy contracts deployed without atomic initialization, which creates
a window for front-running attacks where an attacker can initialize the proxy
before the legitimate owner.

This includes:
- Proxies deployed with empty initialization data
- Proxies where deployment and initialization are in separate transactions
"""

from deployguard.models.rules import Rule, RuleCategory, RuleViolation, Severity
from deployguard.models.static import DeploymentMethod, ScriptAnalysis
from deployguard.rules.base import StaticRule


class NonAtomicInitRule(StaticRule):
    """Detect proxies deployed without atomic initialization.

    This rule checks for proxy deployments where:
    1. The initialization data parameter is empty ("", "0x", or bytes(""))
    2. Deployment and initialization occur in separate transaction boundaries

    The CPIMP (Clandestine Proxy In the Middle of Proxy) attack occurs when:
    1. Proxy is deployed without atomic initialization
    2. Attacker monitors mempool for proxy deployment
    3. Attacker front-runs the initialization transaction
    4. Attacker gains control of the proxy

    Prevention: Pass encoded initialization data directly to the proxy
    constructor within a single transaction boundary.
    """

    def check(self, analysis: ScriptAnalysis) -> list[RuleViolation]:
        """Check for non-atomic proxy initialization.

        Args:
            analysis: Parsed deployment script

        Returns:
            List of violations (one per non-atomic proxy deployment)
        """
        violations = []

        for deployment in analysis.proxy_deployments:
            # Check for empty init data OR non-atomic transaction boundary
            if deployment.has_empty_init or not deployment.is_atomic:
                # Build deployment method context string
                method_str = self._get_deployment_method_str(deployment.deployment_method)

                if deployment.has_empty_init:
                    message = (
                        f"{deployment.proxy_type.value} deployed{method_str} with empty initialization "
                        f"data ('{deployment.init_data_arg}'). This creates a window for "
                        f"front-running attacks where an attacker can initialize the proxy "
                        f"before you."
                    )
                else:
                    message = (
                        f"{deployment.proxy_type.value} deployment{method_str} and initialization "
                        f"occur in separate transactions. This creates a front-running "
                        f"vulnerability where an attacker can initialize the proxy between "
                        f"the deployment and initialization transactions."
                    )

                recommendation = self._get_recommendation(deployment)

                violations.append(
                    RuleViolation(
                        rule=self.rule,
                        severity=self.rule.severity,
                        message=message,
                        recommendation=recommendation,
                        location=deployment.location,
                        context={
                            "proxy_type": deployment.proxy_type.value,
                            "init_data_arg": deployment.init_data_arg,
                            "implementation_arg": deployment.implementation_arg,
                            "proxy_variable": deployment.proxy_variable,
                            "has_empty_init": deployment.has_empty_init,
                            "is_atomic": deployment.is_atomic,
                            "deployment_method": deployment.deployment_method.value,
                            "salt": deployment.salt,
                        },
                    )
                )

        return violations

    def _get_deployment_method_str(self, method: DeploymentMethod) -> str:
        """Get human-readable string for deployment method.

        Args:
            method: Deployment method enum

        Returns:
            String like " via CREATE2" or "" for standard new
        """
        method_strs = {
            DeploymentMethod.NEW: "",
            DeploymentMethod.NEW_CREATE2: " via CREATE2",
            DeploymentMethod.CREATEX: " via CreateX",
            DeploymentMethod.CREATE2_ASSEMBLY: " via CREATE2 assembly",
            DeploymentMethod.CREATE3: " via CREATE3",
        }
        return method_strs.get(method, "")

    def _get_recommendation(self, deployment) -> str:
        """Get recommendation based on deployment method.

        Args:
            deployment: ProxyDeployment instance

        Returns:
            Recommendation string
        """
        if deployment.deployment_method == DeploymentMethod.CREATEX:
            return (
                f"Include initialization data in the proxy bytecode:\n\n"
                f"  // Encode the initialization call\n"
                f"  bytes memory initData = abi.encodeCall({{Contract}}.initialize, ({{args}}));\n\n"
                f"  // Include init data in proxy bytecode\n"
                f"  bytes memory bytecode = abi.encodePacked(\n"
                f"      type({deployment.proxy_type.value}).creationCode,\n"
                f"      abi.encode(impl, initData)  // NOT empty bytes\n"
                f"  );\n"
                f"  createX.deployCreate2(salt, bytecode);\n\n"
                f"See: https://dedaub.com/blog/the-cpimp-attack-an-insanely-far-reaching-vulnerability-successfully-mitigated/"
            )
        elif deployment.deployment_method == DeploymentMethod.NEW_CREATE2:
            return (
                f"Pass initialization data to the proxy constructor:\n\n"
                f"  vm.startBroadcast();\n"
                f"  // Encode the initialization call\n"
                f"  bytes memory data = abi.encodeCall({{Contract}}.initialize, ({{args}}));\n\n"
                f"  // Deploy proxy with CREATE2 and initialization data\n"
                f"  {deployment.proxy_type.value} proxy = new {deployment.proxy_type.value}{{salt: salt}}(\n"
                f"      address(impl),\n"
                f"      data  // NOT empty string\n"
                f"  );\n"
                f"  vm.stopBroadcast();\n\n"
                f"See: https://dedaub.com/blog/the-cpimp-attack-an-insanely-far-reaching-vulnerability-successfully-mitigated/"
            )
        else:
            return (
                f"Pass initialization data to the proxy constructor to make deployment atomic:\n\n"
                f"  vm.startBroadcast();\n"
                f"  // Encode the initialization call\n"
                f"  bytes memory data = abi.encodeCall({{Contract}}.initialize, ({{args}}));\n\n"
                f"  // Deploy proxy with initialization data in same tx\n"
                f"  {deployment.proxy_type.value} proxy = new {deployment.proxy_type.value}(\n"
                f"      address(impl),\n"
                f"      data  // NOT empty string\n"
                f"  );\n"
                f"  vm.stopBroadcast();\n\n"
                f"See: https://dedaub.com/blog/the-cpimp-attack-an-insanely-far-reaching-vulnerability-successfully-mitigated/"
            )


# Create rule instance
RULE_NON_ATOMIC_INIT = Rule(
    rule_id="NON_ATOMIC_INIT",
    name="Non-Atomic Proxy Initialization",
    description="Proxy deployed without atomic initialization (empty init data or separate transactions)",
    severity=Severity.CRITICAL,
    category=RuleCategory.PROXY,
    references=[
        "https://dedaub.com/blog/the-cpimp-attack-an-insanely-far-reaching-vulnerability-successfully-mitigated/",
    ],
    hack_references=[
        "https://rekt.news/uspd-rekt/",
    ],
    real_world_context=(
        "This is vulnerable to a CPIMP (Clandestine Proxy In the Middle of Proxy) attack. "
        "Attackers monitor mempools for proxy deployments with empty init data, then front-run "
        "the initialization transaction to gain admin control. Dedaub identified CPIMP as affecting "
        "thousands of contracts across multiple chains, making it one of the most far-reaching "
        "vulnerabilities ever found."
    ),
    remediation="Ensure proxy initialization is atomic - pass init data to constructor within single tx boundary",
)

# Instantiate rule (will be registered when module is imported)
rule_non_atomic_init = NonAtomicInitRule(RULE_NON_ATOMIC_INIT)
