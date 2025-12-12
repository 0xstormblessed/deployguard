"""TEST_NO_RUN: Test Doesn't Execute Deployment.

Detects test files that import the deployment script but don't actually
call run() to execute the deployment.
"""

import re
from pathlib import Path

from deployguard.models.core import SourceLocation
from deployguard.models.rules import Rule, RuleCategory, RuleViolation, Severity
from deployguard.models.static import ScriptAnalysis
from deployguard.rules.base import StaticRule


class TestNoRunRule(StaticRule):
    """Detect tests that don't execute deployments.

    A deployment test should:
    1. Import the deployment script
    2. Instantiate the deployment contract
    3. Call the run() function
    4. Verify the results

    Tests that import but don't call run() aren't actually testing the deployment.
    """

    # Patterns for run() call
    RUN_CALL_PATTERNS = [
        re.compile(r"\.run\s*\(\s*\)"),
        re.compile(r"deployer\.run\s*\("),
        re.compile(r"script\.run\s*\("),
    ]

    def check(self, analysis: ScriptAnalysis) -> list[RuleViolation]:
        """Check if tests call run().

        Args:
            analysis: Parsed deployment script

        Returns:
            List of violations (one per test that doesn't call run)
        """
        violations = []

        # Check if analysis includes test coverage info
        if hasattr(analysis, "test_coverage") and analysis.test_coverage:
            # Use test coverage data
            for script_path, coverage in analysis.test_coverage.items():
                if coverage.has_any_test and not coverage.test_calls_run:
                    violations.append(
                        self._create_violation(
                            script_path,
                            [f.name for f in coverage.test_files],
                        )
                    )
        else:
            # Fallback: Check test files for run() calls
            script_path = Path(analysis.file_path)
            script_name = script_path.stem.replace(".s", "")
            test_dir = script_path.parent.parent / "test"

            if not test_dir.exists():
                return violations

            # Find test files that might be for this script
            test_files = list(test_dir.glob(f"{script_name}*.t.sol"))
            test_files.extend(test_dir.glob("Deploy*.t.sol"))

            for test_file in test_files:
                try:
                    content = test_file.read_text()

                    # Check if test imports the deployment script
                    has_import = script_name in content or "Deploy" in content

                    # Check if test calls run()
                    has_run_call = any(
                        pattern.search(content) for pattern in self.RUN_CALL_PATTERNS
                    )

                    if has_import and not has_run_call:
                        violations.append(
                            RuleViolation(
                                rule=self.rule,
                                severity=self.rule.severity,
                                message=(
                                    f"Test file '{test_file.name}' imports deployment script "
                                    f"but doesn't call run() to execute the deployment."
                                ),
                                recommendation=(
                                    f"Execute the deployment in your test:\n\n"
                                    f"  function testDeploy() public {{\n"
                                    f"      // Instantiate deployment script\n"
                                    f"      DeployScript deployer = new DeployScript();\n\n"
                                    f"      // Execute deployment\n"
                                    f"      deployer.run();\n\n"
                                    f"      // Verify deployment results\n"
                                    f"      // - Check contracts were deployed\n"
                                    f"      // - Verify initialization\n"
                                    f"      // - Test contract functionality\n"
                                    f"  }}\n\n"
                                    f"The test should actually run the deployment, not just set up mocks."
                                ),
                                location=SourceLocation(file_path=str(test_file), line_number=1),
                                context={
                                    "test_file": test_file.name,
                                    "script": script_name,
                                },
                            )
                        )
                except (IOError, UnicodeDecodeError):
                    continue

        return violations

    def _create_violation(self, script_path: str | Path, test_files: list[str]) -> RuleViolation:
        """Create violation for test that doesn't call run().

        Args:
            script_path: Path to deployment script
            test_files: List of test file names

        Returns:
            RuleViolation instance
        """
        script_name = Path(script_path).name

        return RuleViolation(
            rule=self.rule,
            severity=self.rule.severity,
            message=f"Test doesn't call run() for deployment script: {script_name}",
            recommendation=(
                f"Ensure your test calls the deployment run() function:\n\n"
                f"  DeployScript deployer = new DeployScript();\n"
                f"  deployer.run();  // Actually execute the deployment\n\n"
                f"Then verify the deployment results with assertions."
            ),
            location=SourceLocation(file_path=str(script_path), line_number=1),
            context={
                "script": script_name,
                "test_files": test_files,
            },
        )


# Create rule instance
RULE_TEST_NO_RUN = Rule(
    rule_id="TEST_NO_RUN",
    name="Test Doesn't Execute Deployment",
    description="Test imports deployment script but doesn't call run()",
    severity=Severity.MEDIUM,
    category=RuleCategory.TESTING,
    references=[
        "https://book.getfoundry.sh/forge/tests",
    ],
    remediation="Ensure test calls deployer.run() to execute deployment",
)

rule_test_no_run = TestNoRunRule(RULE_TEST_NO_RUN)
