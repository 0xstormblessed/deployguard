"""DEPLOYER_ADMIN: Deployer Retains Admin Privileges.

Detects when msg.sender (deployer EOA) is explicitly set as the admin
instead of using a secure admin address.
"""

import re

from deployguard.models.core import SourceLocation
from deployguard.models.rules import Rule, RuleCategory, RuleViolation, Severity
from deployguard.models.static import ScriptAnalysis
from deployguard.rules.base import StaticRule


class DeployerAsAdminRule(StaticRule):
    """Detect when deployer address is used as admin.

    Patterns like:
    - new TransparentUpgradeableProxy(impl, msg.sender, data)
    - proxy.changeAdmin(msg.sender)
    - contract.transferOwnership(msg.sender)

    Using msg.sender as admin is problematic even if you later transfer
    ownership, because it explicitly sets up the deployer as admin initially.

    Better approach: Use a predefined admin address from the start.
    """

    # Patterns where msg.sender is used as admin
    MSG_SENDER_ADMIN_PATTERNS = [
        re.compile(r"TransparentUpgradeableProxy\s*\([^,]+,\s*msg\.sender\s*,"),
        re.compile(r"\.changeAdmin\s*\(\s*msg\.sender\s*\)"),
        re.compile(r"\.transferOwnership\s*\(\s*msg\.sender\s*\)"),
        re.compile(r'admin\s*:\s*msg\.sender'),
        re.compile(r"_admin\s*=\s*msg\.sender"),
    ]

    def check(self, analysis: ScriptAnalysis) -> list[RuleViolation]:
        """Check for msg.sender used as admin.

        Args:
            analysis: Parsed deployment script

        Returns:
            List of violations (one per occurrence)
        """
        violations = []

        # Read script source
        try:
            with open(analysis.file_path, "r") as f:
                source_lines = f.readlines()
        except (FileNotFoundError, IOError):
            return violations

        for line_num, line in enumerate(source_lines, 1):
            for pattern in self.MSG_SENDER_ADMIN_PATTERNS:
                if pattern.search(line):
                    message = (
                        f"Deployer (msg.sender) is explicitly set as admin. "
                        f"This creates a temporary security risk even if ownership "
                        f"is transferred later."
                    )
                    violations.append(
                        RuleViolation(
                            rule=self.rule,
                            severity=self.rule.severity,
                            message=message,
                            recommendation=(
                                f"Use a secure admin address from the start:\n\n"
                                f"  // Load admin from environment\n"
                                f"  address admin = vm.envAddress(\"ADMIN_ADDRESS\");\n\n"
                                f"  // Use admin directly (not msg.sender)\n"
                                f"  proxy = new TransparentUpgradeableProxy(\n"
                                f"      address(impl),\n"
                                f"      admin,  // NOT msg.sender\n"
                                f"      data\n"
                                f"  );\n\n"
                                f"Recommended admin addresses:\n"
                                f"  - Gnosis Safe multisig\n"
                                f"  - Timelock contract\n"
                                f"  - DAO governor contract"
                            ),
                            location=SourceLocation(
                                file_path=analysis.file_path,
                                line_number=line_num,
                                line_content=line.strip(),
                            ),
                            context={
                                "pattern": "msg.sender as admin",
                            },
                        )
                    )
                    break  # Only report once per line

        return violations


# Create rule instance
RULE_DEPLOYER_ADMIN = Rule(
    rule_id="DEPLOYER_ADMIN",
    name="Deployer Retains Admin Privileges",
    description="Admin/owner is set to msg.sender (deployer) instead of secure address",
    severity=Severity.MEDIUM,
    category=RuleCategory.SECURITY,
    references=[
        "https://frameworks.securityalliance.org/multisig-for-protocols/overview",
    ],
    remediation="Set admin to a multisig or governance contract address, not msg.sender",
)

rule_deployer_admin = DeployerAsAdminRule(RULE_DEPLOYER_ADMIN)
