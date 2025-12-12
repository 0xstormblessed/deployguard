"""NO_FORK_TEST: No Fork Test for Deployment.

Detects deployments that have tests but no fork tests against real network state.
Fork tests are crucial for verifying deployments work with actual on-chain state.
"""

import re
from pathlib import Path

from deployguard.models.core import SourceLocation
from deployguard.models.rules import Rule, RuleCategory, RuleViolation, Severity
from deployguard.models.static import ScriptAnalysis
from deployguard.rules.base import StaticRule


class NoForkTestRule(StaticRule):
    """Detect deployments without fork tests.

    Fork tests use vm.createSelectFork() to test against real network state,
    which is essential for:
    1. Verifying interactions with existing contracts
    2. Testing gas costs with real data
    3. Catching issues that only appear with real state
    4. Simulating the exact deployment environment
    """

    # Patterns that indicate fork test
    FORK_TEST_PATTERNS = [
        re.compile(r"vm\.createFork\s*\("),
        re.compile(r"vm\.createSelectFork\s*\("),
        re.compile(r"vm\.selectFork\s*\("),
        re.compile(r"fork_url", re.IGNORECASE),
        re.compile(r"mainnet_fork", re.IGNORECASE),
    ]

    def check(self, analysis: ScriptAnalysis) -> list[RuleViolation]:
        """Check for missing fork tests.

        Args:
            analysis: Parsed deployment script

        Returns:
            List of violations (one if tests exist but no fork tests)
        """
        violations = []

        # Check if analysis includes test coverage info
        if hasattr(analysis, "test_coverage") and analysis.test_coverage:
            # Use test coverage data
            for script_path, coverage in analysis.test_coverage.items():
                if coverage.has_any_test and not coverage.has_fork_test:
                    violations.append(
                        self._create_violation(script_path, coverage.test_files)
                    )
        else:
            # Fallback: Check for test files and scan for fork patterns
            script_path = Path(analysis.file_path)
            test_dir = script_path.parent.parent / "test"

            if not test_dir.exists():
                return violations

            # Find test files
            test_files = list(test_dir.glob("*.t.sol"))
            if not test_files:
                return violations  # No tests at all (covered by DG-012)

            # Check if any test file has fork test patterns
            has_fork_test = False
            for test_file in test_files:
                try:
                    content = test_file.read_text()
                    if any(pattern.search(content) for pattern in self.FORK_TEST_PATTERNS):
                        has_fork_test = True
                        break
                except (IOError, UnicodeDecodeError):
                    continue

            if not has_fork_test:
                violations.append(
                    self._create_violation(analysis.file_path, test_files)
                )

        return violations

    def _create_violation(self, script_path: str | Path, test_files: list) -> RuleViolation:
        """Create violation for missing fork test.

        Args:
            script_path: Path to deployment script
            test_files: List of existing test files

        Returns:
            RuleViolation instance
        """
        script_name = Path(script_path).name
        test_names = [Path(t).name if isinstance(t, (str, Path)) else t for t in test_files]

        return RuleViolation(
            rule=self.rule,
            severity=self.rule.severity,
            message=(
                f"Deployment has tests but no fork test against mainnet state. "
                f"Fork tests are essential for verifying deployment works with real contracts."
            ),
            recommendation=(
                f"Add a fork test to verify deployment against real network state:\n\n"
                f"  contract DeployForkTest is Test {{\n"
                f"      function testDeployOnFork() public {{\n"
                f"          // Fork mainnet (or target network)\n"
                f"          vm.createSelectFork(vm.envString(\"MAINNET_RPC_URL\"));\n\n"
                f"          // Run deployment\n"
                f"          DeployScript deployer = new DeployScript();\n"
                f"          deployer.run();\n\n"
                f"          // Verify deployment\n"
                f"          // - Check proxy points to correct implementation\n"
                f"          // - Verify initialized correctly\n"
                f"          // - Test interactions with existing contracts\n"
                f"      }}\n"
                f"  }}\n\n"
                f"Run with: forge test --fork-url $MAINNET_RPC_URL\n\n"
                f"See: https://book.getfoundry.sh/forge/fork-testing"
            ),
            location=SourceLocation(file_path=str(script_path), line_number=1),
            context={
                "script": script_name,
                "test_files": test_names,
                "recommendation_detail": "Add vm.createSelectFork() to test",
            },
        )


# Create rule instance
RULE_NO_FORK_TEST = Rule(
    rule_id="NO_FORK_TEST",
    name="No Fork Test for Deployment",
    description="Deployment has tests but no fork test against mainnet state",
    severity=Severity.MEDIUM,
    category=RuleCategory.TESTING,
    references=[
        "https://book.getfoundry.sh/forge/fork-testing",
        "https://book.getfoundry.sh/tutorials/best-practices#fork-testing",
    ],
    remediation="Add a fork test using vm.createSelectFork()",
)

rule_no_fork_test = NoForkTestRule(RULE_NO_FORK_TEST)
