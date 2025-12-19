"""Test file matching utilities.

This module provides functions for finding and matching test files to deployment
scripts in Foundry projects.
"""

import re
from pathlib import Path

from deployguard.models.testing import FoundryProject

# Regex patterns for detecting deployment script imports
IMPORT_PATTERNS = [
    # import "../script/Deploy.s.sol";
    r'import\s+["\']\.\.\/script\/(\w+)\.s\.sol["\'];',
    # import {Deploy} from "../script/Deploy.s.sol";
    r'import\s+\{[^}]+\}\s+from\s+["\']\.\.\/script\/(\w+)\.s\.sol["\'];',
    # import "script/Deploy.s.sol";
    r'import\s+["\']script\/(\w+)\.s\.sol["\'];',
    # import {Deploy} from "script/Deploy.s.sol";
    r'import\s+\{[^}]+\}\s+from\s+["\']script\/(\w+)\.s\.sol["\'];',
]

# Patterns to detect if test actually calls deployment
RUN_CALL_PATTERNS = [
    # deployer.run()
    r'(\w+)\.run\s*\(\s*\)',
    # deployer.run(args)
    r'(\w+)\.run\s*\([^)]+\)',
    # Script(deployer).run()
    r'\w+\([^)]*\)\.run\s*\(',
]

# Patterns to detect fork tests
FORK_PATTERNS = [
    # vm.createFork
    r'vm\.createFork\s*\(',
    # vm.createSelectFork
    r'vm\.createSelectFork\s*\(',
    # vm.selectFork
    r'vm\.selectFork\s*\(',
    # Fork in contract name
    r'contract\s+\w*[Ff]ork\w*\s+is',
]


def find_test_files(deploy_script: Path, project: FoundryProject) -> list[Path]:
    """Find test files that might test a deployment script.

    This function looks for test files using common naming conventions,
    searching recursively through all subdirectories:
    - Deploy.s.sol → **/Deploy.t.sol
    - Deploy.s.sol → **/DeployTest.t.sol
    - Deploy.s.sol → **/Deploy.fork.t.sol

    Args:
        deploy_script: Path to deployment script
        project: FoundryProject containing the script

    Returns:
        List of test file paths that exist

    Example:
        >>> project = FoundryProject.detect(Path.cwd())
        >>> script = project.script_dir / "Deploy.s.sol"
        >>> tests = find_test_files(script, project)
        >>> print(f"Found {len(tests)} test files")
    """
    test_dir = project.test_dir
    script_name = deploy_script.stem.replace(".s", "")  # Deploy.s.sol → Deploy

    if not test_dir.exists():
        return []

    matches = []

    # Search recursively for matching test files
    # Pattern 1: Direct name match - Deploy.t.sol
    matches.extend(test_dir.glob(f"**/{script_name}.t.sol"))

    # Pattern 2: Test suffix - DeployTest.t.sol
    matches.extend(test_dir.glob(f"**/{script_name}Test.t.sol"))

    # Pattern 3: Fork test - Deploy.fork.t.sol
    matches.extend(test_dir.glob(f"**/{script_name}.fork.t.sol"))

    # Remove duplicates and return
    return list(set(matches))


def find_imported_scripts(test_content: str) -> list[str]:
    """Extract deployment script names from test file imports.

    This function searches for import statements that reference deployment
    scripts (*.s.sol files) and extracts the script names.

    Args:
        test_content: Contents of the test file as a string

    Returns:
        List of deployment script names (without .s.sol extension)

    Example:
        >>> content = 'import "../script/Deploy.s.sol";'
        >>> scripts = find_imported_scripts(content)
        >>> print(scripts)  # ['Deploy']
    """
    scripts = []
    for pattern in IMPORT_PATTERNS:
        matches = re.findall(pattern, test_content)
        scripts.extend(matches)
    return list(set(scripts))  # Remove duplicates


def check_test_calls_run(test_content: str) -> bool:
    """Check if test actually executes the deployment.

    This function looks for patterns like:
    - deployer.run()
    - deployer.run(args)
    - Script(deployer).run()

    Args:
        test_content: Contents of the test file as a string

    Returns:
        True if the test calls run(), False otherwise

    Example:
        >>> content = '''
        ... function test_deployment() public {
        ...     Deploy deployer = new Deploy();
        ...     deployer.run();
        ... }
        ... '''
        >>> test_calls_run(content)
        True
    """
    for pattern in RUN_CALL_PATTERNS:
        if re.search(pattern, test_content):
            return True
    return False


def is_fork_test(test_content: str) -> bool:
    """Check if test file contains fork testing.

    This function looks for patterns like:
    - vm.createFork(...)
    - vm.createSelectFork(...)
    - vm.selectFork(...)
    - contract ForkTest is Test

    Args:
        test_content: Contents of the test file as a string

    Returns:
        True if the test uses fork mode, False otherwise

    Example:
        >>> content = '''
        ... contract DeployForkTest is Test {
        ...     function setUp() public {
        ...         vm.createSelectFork("mainnet");
        ...     }
        ... }
        ... '''
        >>> is_fork_test(content)
        True
    """
    for pattern in FORK_PATTERNS:
        if re.search(pattern, test_content):
            return True
    return False


def find_all_importing_tests(
    deploy_script: Path, project: FoundryProject
) -> list[Path]:
    """Find all test files that import a deployment script.

    This function scans all test files in the project and returns those
    that import the specified deployment script.

    Args:
        deploy_script: Path to deployment script
        project: FoundryProject containing the script

    Returns:
        List of test file paths that import the script
    """
    script_name = deploy_script.stem.replace(".s", "")
    importing_tests = []

    for test_file in project.test_files:
        try:
            content = test_file.read_text(encoding="utf-8")
            imported_scripts = find_imported_scripts(content)
            if script_name in imported_scripts:
                importing_tests.append(test_file)
        except (OSError, UnicodeDecodeError):
            # Skip files that can't be read
            continue

    return importing_tests


def find_fork_tests(test_files: list[Path]) -> list[Path]:
    """Find which test files use fork testing.

    Args:
        test_files: List of test file paths to check

    Returns:
        List of test files that use fork mode
    """
    fork_tests = []

    for test_file in test_files:
        try:
            content = test_file.read_text(encoding="utf-8")
            if is_fork_test(content):
                fork_tests.append(test_file)
        except (OSError, UnicodeDecodeError):
            # Skip files that can't be read
            continue

    return fork_tests
