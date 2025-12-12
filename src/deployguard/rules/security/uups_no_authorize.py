"""UUPS_NO_AUTHORIZE: UUPS Proxy Missing _authorizeUpgrade Override.

Detects UUPS proxies where the implementation contract does not properly
override _authorizeUpgrade() with access control checks.
"""

import re

from deployguard.models.core import SourceLocation
from deployguard.models.rules import Rule, RuleCategory, RuleViolation, Severity
from deployguard.models.static import ProxyType, ScriptAnalysis
from deployguard.rules.base import StaticRule


class UUPSMissingAuthorizeUpgradeRule(StaticRule):
    """Detect UUPS proxies without proper _authorizeUpgrade override.

    UUPS (Universal Upgradeable Proxy Standard) proxies require the implementation
    contract to override _authorizeUpgrade() to control who can upgrade the proxy.
    Without this override, anyone can upgrade the proxy, leading to critical security issues.

    This is a simplified check that warns when UUPS proxies are detected.
    Full implementation would require AST parsing of the implementation contract.
    """

    # Patterns that indicate UUPS proxy deployment
    UUPS_PROXY_PATTERNS = [
        re.compile(r"\bUUPSUpgradeable\b"),
        re.compile(r"\bUUPSProxy\b"),
        re.compile(r"ERC1967Proxy.*UUPS"),
    ]

    def check(self, analysis: ScriptAnalysis) -> list[RuleViolation]:
        """Check for UUPS proxies and warn about _authorizeUpgrade.

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

        if not uups_deployments:
            # Check if script mentions UUPS in source (might be custom deployment)
            try:
                with open(analysis.file_path, "r") as f:
                    source_code = f.read()
                has_uups_mention = any(p.search(source_code) for p in self.UUPS_PROXY_PATTERNS)
                if not has_uups_mention:
                    return violations
            except (FileNotFoundError, IOError):
                return violations

        # For each UUPS deployment, warn about _authorizeUpgrade requirement
        for deployment in uups_deployments:
            message = (
                f"UUPS proxy detected. CRITICAL: Ensure the implementation contract "
                f"overrides _authorizeUpgrade() with proper access control. "
                f"Without this, anyone can upgrade the proxy to malicious code."
            )

            violations.append(
                RuleViolation(
                    rule=self.rule,
                    severity=self.rule.severity,
                    message=message,
                    recommendation=(
                        f"Ensure your UUPS implementation contract includes:\n\n"
                        f"  import \"@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol\";\n\n"
                        f"  contract MyContract is UUPSUpgradeable, OwnableUpgradeable {{\n"
                        f"      // REQUIRED: Override with access control\n"
                        f"      function _authorizeUpgrade(address newImplementation)\n"
                        f"          internal\n"
                        f"          override\n"
                        f"          onlyOwner  // Or other access control\n"
                        f"      {{\n"
                        f"          // Only owner can upgrade\n"
                        f"      }}\n"
                        f"  }}\n\n"
                        f"Without this override, the proxy is vulnerable to unauthorized upgrades!\n\n"
                        f"See: https://docs.openzeppelin.com/contracts/4.x/api/proxy#UUPSUpgradeable"
                    ),
                    location=deployment.location,
                    context={
                        "proxy_type": deployment.proxy_type.value,
                        "implementation": deployment.implementation_arg,
                        "check_type": "uups_authorize_upgrade",
                        "note": "Manual verification required for implementation contract",
                    },
                )
            )

        return violations


# Create rule instance
RULE_UUPS_NO_AUTHORIZE = Rule(
    rule_id="UUPS_NO_AUTHORIZE",
    name="UUPS Proxy Missing _authorizeUpgrade Override",
    description="UUPS proxy implementation must override _authorizeUpgrade for access control",
    severity=Severity.CRITICAL,
    category=RuleCategory.SECURITY,
    references=[
        "https://docs.openzeppelin.com/contracts/4.x/api/proxy#UUPSUpgradeable-_authorizeUpgrade-address-",
    ],
    hack_references=[],
    real_world_context=(
        "UUPS proxies require the implementation to override _authorizeUpgrade() with access control. "
        "Without this, anyone can call upgradeTo() and replace the implementation with malicious code. "
        "This function must include authorization logic (e.g., onlyOwner) to restrict who can upgrade."
    ),
    remediation="Override _authorizeUpgrade() in implementation contract with access control checks",
)

rule_uups_no_authorize = UUPSMissingAuthorizeUpgradeRule(RULE_UUPS_NO_AUTHORIZE)
