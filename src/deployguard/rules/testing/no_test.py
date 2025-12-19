"""NO_TEST: Deployment Script Has No Test.

Detects deployment scripts that don't have corresponding test files,
which means the deployment hasn't been tested.
"""

from pathlib import Path

from deployguard.models.core import SourceLocation
from deployguard.models.rules import Rule, RuleCategory, RuleViolation, Severity
from deployguard.models.static import ScriptAnalysis
from deployguard.models.testing import FoundryProject
from deployguard.rules.base import StaticRule
from deployguard.testing.matcher import find_test_files


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
        """
        violations = []
        script_path = Path(analysis.file_path)
        script_name = script_path.stem.replace(".s", "")

        # Try to detect Foundry project and use find_test_files
        project = FoundryProject.detect(script_path)
        if project:
            test_files = find_test_files(script_path, project)
            has_test = len(test_files) > 0
            test_dir = project.test_dir
        else:
            # Fallback if no Foundry project detected
            test_dir = script_path.parent.parent / "test"
            has_test = False

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
