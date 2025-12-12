"""PRIVATE_KEY_ENV: Private Key in Environment Variable.

Detects when deployment scripts load private keys from .env files,
which is a security risk.
"""

import re

from deployguard.models.core import SourceLocation
from deployguard.models.rules import Rule, RuleCategory, RuleViolation, Severity
from deployguard.models.static import ScriptAnalysis
from deployguard.rules.base import StaticRule


class PrivateKeyEnvRule(StaticRule):
    """Detect private key loading from environment variables.

    Using .env files for private keys is risky because:
    1. .env files can be accidentally committed to git
    2. Environment variables may be logged or exposed in CI/CD
    3. No hardware security module (HSM) protection
    4. Keys stored in plaintext on disk

    Best practices:
    - Use hardware wallets (--ledger, --trezor)
    - Use encrypted keystore files
    - Use secure key management services (Vault, AWS KMS)
    """

    # Patterns that indicate private key loading from env
    PRIVATE_KEY_PATTERNS = [
        re.compile(r'vm\.envUint\s*\(\s*["\']PRIVATE_KEY["\']\s*\)'),
        re.compile(r'vm\.envUint\s*\(\s*["\']DEPLOYER_PRIVATE_KEY["\']\s*\)'),
        re.compile(r'vm\.envUint\s*\(\s*["\']PK["\']\s*\)'),
        re.compile(r'vm\.envBytes32\s*\(\s*["\']PRIVATE_KEY["\']\s*\)'),
        re.compile(r'vm\.envOr\s*\([^)]*PRIVATE_KEY[^)]*\)', re.IGNORECASE),
        re.compile(r'vm\.envUint\s*\(\s*["\']OWNER_PRIVATE_KEY["\']\s*\)'),
        re.compile(r'vm\.envUint\s*\(\s*["\']ADMIN_PRIVATE_KEY["\']\s*\)'),
    ]

    def check(self, analysis: ScriptAnalysis) -> list[RuleViolation]:
        """Check for private key loading from environment variables.

        Args:
            analysis: Parsed deployment script

        Returns:
            List of violations (one per private key env load)
        """
        violations = []

        # Read script source line by line
        try:
            with open(analysis.file_path, "r") as f:
                source_lines = f.readlines()
        except (FileNotFoundError, IOError):
            # Can't read file, skip this rule
            return violations

        for line_num, line in enumerate(source_lines, 1):
            for pattern in self.PRIVATE_KEY_PATTERNS:
                if pattern.search(line):
                    message = (
                        f"Private key loaded from environment variable. "
                        f"This risks exposure through accidental commits, logs, or CI/CD systems."
                    )
                    violations.append(
                        RuleViolation(
                            rule=self.rule,
                            severity=self.rule.severity,
                            message=message,
                            recommendation=(
                                f"Use secure key management instead of .env files:\n\n"
                                f"  Option 1: Hardware wallet (Recommended)\n"
                                f"    forge script Deploy.s.sol --ledger\n\n"
                                f"  Option 2: Encrypted keystore\n"
                                f"    forge script Deploy.s.sol --keystore ~/.foundry/keystores/deployer\n\n"
                                f"  Option 3: Interactive prompt\n"
                                f"    forge script Deploy.s.sol --interactive\n\n"
                                f"See: https://book.getfoundry.sh/reference/forge/forge-script#wallet-options---raw"
                            ),
                            location=SourceLocation(
                                file_path=analysis.file_path,
                                line_number=line_num,
                                line_content=line.strip(),
                            ),
                            context={
                                "risk": "Private keys in .env can be accidentally committed or exposed",
                                "env_variable": self._extract_env_var(line),
                            },
                        )
                    )
                    break  # Only report once per line

        return violations

    def _extract_env_var(self, line: str) -> str:
        """Extract environment variable name from line.

        Args:
            line: Source code line

        Returns:
            Environment variable name if found
        """
        match = re.search(r'["\'](\w*PRIVATE_KEY\w*)["\']', line, re.IGNORECASE)
        return match.group(1) if match else "PRIVATE_KEY"


# Create rule instance
RULE_PRIVATE_KEY_ENV = Rule(
    rule_id="PRIVATE_KEY_ENV",
    name="Private Key in Environment Variable",
    description="Script loads private key from .env file, risking exposure",
    severity=Severity.HIGH,
    category=RuleCategory.SECURITY,
    references=[
        "https://getfoundry.sh/guides/best-practices/key-management",
        "https://github.com/smartcontractkit/full-blockchain-solidity-course-js/discussions/5",
    ],
    hack_references=[
        "https://rekt.news/okx-dex-rekt",
    ],
    real_world_context=(
        "Private keys stored in .env files have been accidentally committed to public repositories countless times. "
        "In 2023, GitHub rotated keys after a vulnerability exposed credentials in environment files. "
        "Attackers actively scan GitHub for committed .env files and immediately drain any funds found. "
        "Even if not committed, .env files can be exposed through log files, CI/CD artifacts, or compromised systems."
    ),
    remediation="Use hardware wallet (--ledger) or keystore file instead of .env for private keys",
)

rule_private_key_env = PrivateKeyEnvRule(RULE_PRIVATE_KEY_ENV)
