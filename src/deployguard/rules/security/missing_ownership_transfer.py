"""MISSING_OWNERSHIP_TRANSFER: Missing Ownership Transfer.

Detects when Ownable contracts are deployed but ownership is not transferred
to a secure admin address (multisig, timelock, or DAO).
"""

import re

from deployguard.models.core import SourceFragment, SourceLocation
from deployguard.models.rules import Rule, RuleCategory, RuleViolation, Severity
from deployguard.models.static import ScriptAnalysis
from deployguard.rules.base import StaticRule


class MissingOwnershipTransferRule(StaticRule):
    """Detect missing ownership transfer after deployment.

    Contracts inheriting from Ownable, AccessControl, or similar access control
    mechanisms should transfer ownership/admin rights from the deployer EOA to:
    - A multisig wallet (e.g., Gnosis Safe)
    - A timelock contract
    - A DAO governance contract

    Leaving ownership with the deployer EOA is a security risk because:
    1. EOA private keys can be compromised
    2. Single point of failure
    3. No transparency or governance
    """

    # Patterns that indicate ownership transfer
    TRANSFER_PATTERNS = [
        re.compile(r"\.transferOwnership\s*\("),
        re.compile(r"\.transferAdmin\s*\("),
        re.compile(r"\.changeAdmin\s*\("),
        re.compile(r"\.setOwner\s*\("),
        re.compile(r"\.grantRole\s*\([^)]*DEFAULT_ADMIN_ROLE"),
        re.compile(r"\.renounceOwnership\s*\("),
    ]

    # Patterns that indicate Ownable contracts
    OWNABLE_PATTERNS = [
        re.compile(r"\bOwnable\b"),
        re.compile(r"\bAccessControl\b"),
        re.compile(r"\bowner\s*\(\s*\)"),
        re.compile(r"\bOnlyOwner\b", re.IGNORECASE),
    ]

    def check(self, analysis: ScriptAnalysis) -> list[RuleViolation]:
        """Check for missing ownership transfer.

        Args:
            analysis: Parsed deployment script

        Returns:
            List of violations (at most one, for the whole script)
        """
        violations = []

        # Read script source
        try:
            with open(analysis.file_path, "r") as f:
                source_code = f.read()
        except (FileNotFoundError, IOError):
            return violations

        # Check if script deploys Ownable-like contracts
        has_ownable_deployment = any(
            pattern.search(source_code) for pattern in self.OWNABLE_PATTERNS
        )

        if not has_ownable_deployment:
            # No Ownable contracts, rule doesn't apply
            return violations

        # Check if ownership is transferred
        has_transfer = any(pattern.search(source_code) for pattern in self.TRANSFER_PATTERNS)

        if not has_transfer:
            message = (
                f"Deployment script contains Ownable/AccessControl contracts but "
                f"does not transfer ownership. Deployer EOA retains admin privileges, "
                f"creating a single point of failure."
            )

            violations.append(
                RuleViolation(
                    rule=self.rule,
                    severity=self.rule.severity,
                    message=message,
                    recommendation=(
                        f"Transfer ownership to a secure admin address:\n\n"
                        f"  Option 1: Multisig wallet (Recommended)\n"
                        f"    contract.transferOwnership(MULTISIG_ADDRESS);\n\n"
                        f"  Option 2: Timelock contract\n"
                        f"    contract.transferOwnership(address(timelock));\n\n"
                        f"  Option 3: DAO governance\n"
                        f"    contract.transferOwnership(GOVERNOR_ADDRESS);\n\n"
                        f"Load the admin address from environment:\n"
                        f"    address admin = vm.envAddress(\"ADMIN_ADDRESS\");\n"
                        f"    contract.transferOwnership(admin);"
                    ),
                    location=SourceLocation(file_path=analysis.file_path, line_number=1),
                    context={
                        "has_ownable_pattern": True,
                        "has_transfer": False,
                        "recommendation_detail": "Add transferOwnership() call before deployment ends",
                    },
                )
            )

        return violations


# Create rule instance
RULE_MISSING_OWNERSHIP_TRANSFER = Rule(
    rule_id="MISSING_OWNERSHIP_TRANSFER",
    name="Missing Ownership Transfer",
    description="Deployed contract ownership not transferred to an admin/multisig",
    severity=Severity.HIGH,
    category=RuleCategory.SECURITY,
    references=[
        "https://frameworks.securityalliance.org/multisig-for-protocols/overview",
    ],
    remediation="Add transferOwnership() call to transfer ownership to a multisig",
)

rule_missing_ownership_transfer = MissingOwnershipTransferRule(RULE_MISSING_OWNERSHIP_TRANSFER)
