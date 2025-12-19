"""HARDCODED_ADDRESS: Hardcoded Address Without Environment Variable.

Detects hardcoded Ethereum addresses that should be configurable via
environment variables or configuration files.
"""

import re

from deployguard.models.core import SourceLocation
from deployguard.models.rules import Rule, RuleCategory, RuleViolation, Severity
from deployguard.models.static import ScriptAnalysis
from deployguard.rules.base import StaticRule


class HardcodedAddressRule(StaticRule):
    """Detect hardcoded addresses that should be configurable.

    Hardcoding addresses makes scripts:
    1. Network-specific (can't easily deploy to different networks)
    2. Hard to maintain (address changes require code changes)
    3. Error-prone (typos in addresses)
    4. Difficult to audit (addresses scattered throughout code)

    Best practice: Load addresses from environment variables or config files.
    """

    # Pattern for Ethereum addresses
    ADDRESS_PATTERN = re.compile(r'0x[a-fA-F0-9]{40}')

    # Patterns that indicate proper environment usage (exclude these)
    ENV_PATTERNS = [
        re.compile(r'vm\.envAddress\s*\('),
        re.compile(r'vm\.envOr\s*\('),
        re.compile(r'process\.env\.'),
        re.compile(r'config\['),  # Config file access
        re.compile(r'\.toml'),    # TOML config
    ]

    # Common constants that are OK to hardcode
    ALLOWED_ADDRESSES = {
        "0x0000000000000000000000000000000000000000",  # Zero address
        "0x000000000000000000000000000000000000dEaD",  # Burn address
        "0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE",  # ETH placeholder
    }

    def check(self, analysis: ScriptAnalysis) -> list[RuleViolation]:
        """Check for hardcoded addresses.

        Args:
            analysis: Parsed deployment script

        Returns:
            List of violations (one per hardcoded address)
        """
        violations = []

        # Read script source
        try:
            with open(analysis.file_path, "r") as f:
                source_lines = f.readlines()
        except (FileNotFoundError, IOError):
            return violations

        for line_num, line in enumerate(source_lines, 1):
            # Find all addresses in this line
            addresses = self.ADDRESS_PATTERN.findall(line)

            for address in addresses:
                # Skip allowed addresses (zero, burn, etc.)
                if address in self.ALLOWED_ADDRESSES:
                    continue

                # Check if this address is used with environment variables
                is_env_usage = any(pattern.search(line) for pattern in self.ENV_PATTERNS)

                if not is_env_usage:
                    # This is a hardcoded address
                    violations.append(
                        RuleViolation(
                            rule=self.rule,
                            severity=self.rule.severity,
                            message=(
                                f"Hardcoded address found: {address}. "
                                f"This makes the script network-specific and hard to maintain."
                            ),
                            recommendation=(
                                f"For multichain deployments consider using Foundry configuration "
                                f"TOML files or environment variables for addresses:\n\n"
                                f"  // Using TOML config (recommended):\n"
                                f"  _loadConfig(\"./deployments.toml\", true);\n"
                                f"  address weth = config.get(\"weth\").toAddress();\n"
                                f"  address usdc = config.get(\"usdc\").toAddress();\n\n"
                                f"  // Or use environment variable:\n"
                                f"  address admin = vm.envAddress(\"ADMIN_ADDRESS\");\n\n"
                                f"See: https://getfoundry.sh/guides/scripting-with-config\n\n"
                                f"Benefits:\n"
                                f"  - Easy to deploy to different networks\n"
                                f"  - Addresses in one place (config or .env)\n"
                                f"  - Less prone to typos\n"
                                f"  - Easier to audit"
                            ),
                            location=SourceLocation(
                                file_path=analysis.file_path,
                                line_number=line_num,
                                line_content=line.strip(),
                            ),
                            context={
                                "address": address,
                                "suggestion": "Use vm.envAddress() to load from environment",
                            },
                        )
                    )

        return violations


# Create rule instance
RULE_HARDCODED_ADDRESS = Rule(
    rule_id="HARDCODED_ADDRESS",
    name="Hardcoded Address Without Environment",
    description="Address is hardcoded instead of using environment variable",
    severity=Severity.MEDIUM,
    category=RuleCategory.CONFIG,
    references=[
        "https://book.getfoundry.sh/cheatcodes/env-address",
        "https://book.getfoundry.sh/tutorials/best-practices#use-environment-variables",
        "https://getfoundry.sh/guides/scripting-with-config",
    ],
    remediation="Prefer loading addresses from configuration files, use vm.envAddress() or environment variables for addresses",
)

rule_hardcoded_address = HardcodedAddressRule(RULE_HARDCODED_ADDRESS)
