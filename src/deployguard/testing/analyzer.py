"""Test coverage analyzer for deployment scripts.

This module provides the main analysis functions for checking test coverage
of Foundry deployment scripts.
"""

from pathlib import Path

from deployguard.models.testing import CoverageAnalysis, FoundryProject, ScriptTestCoverage
from deployguard.testing.matcher import (
    check_test_calls_run,
    find_all_importing_tests,
    find_fork_tests,
    find_test_files,
)


def check_script_coverage(
    deploy_script: Path, project: FoundryProject
) -> ScriptTestCoverage:
    """Check test coverage for a single deployment script.

    This function analyzes a deployment script to determine:
    - If it has any test files
    - If the tests import the script
    - If the tests call the run() function
    - If there are fork tests

    Args:
        deploy_script: Path to deployment script
        project: FoundryProject containing the script

    Returns:
        ScriptTestCoverage object with coverage information

    Example:
        >>> project = FoundryProject.detect(Path.cwd())
        >>> script = project.script_dir / "Deploy.s.sol"
        >>> coverage = check_script_coverage(script, project)
        >>> if coverage.has_any_test:
        ...     print("Script has test coverage!")
    """
    # Find test files by naming convention
    test_files = find_test_files(deploy_script, project)

    # Find all tests that import this script
    importing_tests = find_all_importing_tests(deploy_script, project)

    # Combine both - tests found by name or by import
    all_test_files = list(set(test_files + importing_tests))

    # Check for fork tests
    fork_tests = find_fork_tests(all_test_files)

    # Check if any test calls run()
    calls_run = False
    for test_file in all_test_files:
        try:
            content = test_file.read_text(encoding="utf-8")
            if check_test_calls_run(content):
                calls_run = True
                break
        except (OSError, UnicodeDecodeError):
            continue

    return ScriptTestCoverage(
        deploy_script=deploy_script,
        test_files=all_test_files,
        has_any_test=len(all_test_files) > 0,
        has_fork_test=len(fork_tests) > 0,
        test_calls_run=calls_run,
        importing_tests=importing_tests,
        fork_tests=fork_tests,
    )


def analyze_test_coverage(project: FoundryProject) -> CoverageAnalysis:
    """Analyze test coverage for all deployment scripts in a project.

    This function performs a complete test coverage analysis for all
    deployment scripts found in the Foundry project.

    Args:
        project: FoundryProject to analyze

    Returns:
        CoverageAnalysis with complete coverage information

    Example:
        >>> project = FoundryProject.detect(Path.cwd())
        >>> analysis = analyze_test_coverage(project)
        >>> print(f"Scripts with tests: {analysis.scripts_with_tests}")
        >>> print(f"Scripts without tests: {analysis.scripts_without_tests}")
    """
    coverage_map: dict[Path, ScriptTestCoverage] = {}

    # Analyze each deployment script
    for deploy_script in project.deploy_scripts:
        coverage = check_script_coverage(deploy_script, project)
        coverage_map[deploy_script] = coverage

    # Calculate summary statistics
    scripts_with_tests = sum(
        1 for cov in coverage_map.values() if cov.has_any_test
    )
    scripts_without_tests = sum(
        1 for cov in coverage_map.values() if not cov.has_any_test
    )
    scripts_with_fork_tests = sum(
        1 for cov in coverage_map.values() if cov.has_fork_test
    )

    return CoverageAnalysis(
        project_root=project.root,
        deploy_scripts=project.deploy_scripts,
        test_files=project.test_files,
        coverage=coverage_map,
        scripts_with_tests=scripts_with_tests,
        scripts_without_tests=scripts_without_tests,
        scripts_with_fork_tests=scripts_with_fork_tests,
    )


def analyze_test_coverage_from_path(start_path: Path | str) -> CoverageAnalysis | None:
    """Analyze test coverage starting from a given path.

    This is a convenience function that detects the Foundry project and
    performs the analysis in one step.

    Args:
        start_path: Path to start from (file or directory)

    Returns:
        CoverageAnalysis if a Foundry project is found, None otherwise

    Example:
        >>> analysis = analyze_test_coverage_from_path(".")
        >>> if analysis:
        ...     for script, cov in analysis.coverage.items():
        ...         status = "✓" if cov.has_any_test else "✗"
        ...         print(f"{status} {script.name}")
    """
    if isinstance(start_path, str):
        start_path = Path(start_path)

    project = FoundryProject.detect(start_path)
    if not project:
        return None

    return analyze_test_coverage(project)
