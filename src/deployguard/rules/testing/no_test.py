"""NO_TEST: Deployment Script Has No Test.

Detects deployment scripts that don't have corresponding test files,
which means the deployment hasn't been tested.
"""

from pathlib import Path

from deployguard.models.core import SourceLocation
from deployguard.models.rules import Rule, RuleCategory, RuleViolation, Severity
from deployguard.models.static import ScriptAnalysis
from deployguard.rules.base import StaticRule


class NoTestRule(StaticRule):
    """Detect deployment scripts without test coverage.

    Every deployment script should have at least one test file that:
    1. Imports the deployment script
    2. Tests the deployment process
    3. Verifies the deployed contracts work as expected

    This helps catch deployment issues before they reach production.
    """

    def check(self, analysis: ScriptAnalysis) -> list[RuleViolation]:
        """Check for missing test files.

        Args:
            analysis: Parsed deployment script

        Returns:
            List of violations (one if no tests found)

        Note:
            This rule requires test coverage analysis to be added to ScriptAnalysis.
            For now, it performs basic heuristic checks.
        """
        violations = []

        # Check if analysis includes test coverage info
        if hasattr(analysis, "test_coverage") and analysis.test_coverage:
            # Use test coverage data if available
            for script_path, coverage in analysis.test_coverage.items():
                if not coverage.has_any_test:
                    script_name = Path(script_path).name
                    expected_test = f"test/{Path(script_path).stem.replace('.s', '')}.t.sol"

                    violations.append(
                        RuleViolation(
                            rule=self.rule,
                            severity=self.rule.severity,
                            message=f"No test file found for deployment script: {script_name}",
                            recommendation=(
                                f"Create a test file for this deployment script:\n\n"
                                f"  1. Create {expected_test}\n"
                                f"  2. Import the deployment script\n"
                                f"  3. Test the deployment in a fork test\n\n"
                                f"Example test structure:\n"
                                f"  // SPDX-License-Identifier: MIT\n"
                                f"  pragma solidity ^0.8.0;\n\n"
                                f"  import \"forge-std/Test.sol\";\n"
                                f"  import \"../script/{script_name}\";\n\n"
                                f"  contract DeployTest is Test {{\n"
                                f"      DeployScript deployer;\n\n"
                                f"      function setUp() public {{\n"
                                f"          deployer = new DeployScript();\n"
                                f"      }}\n\n"
                                f"      function testDeploy() public {{\n"
                                f"          deployer.run();\n"
                                f"          // Add assertions\n"
                                f"      }}\n"
                                f"  }}\n\n"
                                f"See: https://book.getfoundry.sh/forge/tests"
                            ),
                            location=SourceLocation(file_path=str(script_path), line_number=1),
                            context={
                                "script": script_name,
                                "expected_test": expected_test,
                            },
                        )
                    )
        else:
            # Fallback: Basic heuristic check for test file existence
            script_path = Path(analysis.file_path)
            script_name = script_path.stem.replace(".s", "")
            test_dir = script_path.parent.parent / "test"

            # Look for potential test files
            potential_tests = [
                test_dir / f"{script_name}.t.sol",
                test_dir / f"{script_name}Test.t.sol",
                test_dir / f"Deploy.t.sol",  # Common name
            ]

            has_test = any(t.exists() for t in potential_tests if test_dir.exists())

            if not has_test:
                violations.append(
                    RuleViolation(
                        rule=self.rule,
                        severity=self.rule.severity,
                        message=(
                            f"No test file found for deployment script. "
                            f"Deployment scripts should be tested before production use."
                        ),
                        recommendation=(
                            f"Create a test file for this deployment:\n\n"
                            f"  Expected location: {test_dir}/{script_name}.t.sol\n\n"
                            f"  Test should:\n"
                            f"    1. Import and instantiate the deployment script\n"
                            f"    2. Call the run() function\n"
                            f"    3. Verify deployed contracts work correctly\n"
                            f"    4. Test edge cases and failure scenarios\n\n"
                            f"  For production deployments, use fork testing:\n"
                            f"    vm.createSelectFork(\"mainnet\");\n"
                            f"    deployer.run();\n\n"
                            f"See: https://book.getfoundry.sh/forge/fork-testing"
                        ),
                        location=SourceLocation(file_path=analysis.file_path, line_number=1),
                        context={
                            "script_path": str(script_path),
                            "test_dir": str(test_dir),
                            "expected_tests": [str(t) for t in potential_tests],
                        },
                    )
                )

        return violations


# Create rule instance
RULE_NO_TEST = Rule(
    rule_id="NO_TEST",
    name="Deployment Script Has No Test",
    description="No test file found for deployment script",
    severity=Severity.HIGH,
    category=RuleCategory.TESTING,
    references=[
        "https://book.getfoundry.sh/forge/tests",
        "https://book.getfoundry.sh/tutorials/best-practices#testing-deployments",
    ],
    remediation="Create a test file that imports and executes the deployment",
)

rule_no_test = NoTestRule(RULE_NO_TEST)
