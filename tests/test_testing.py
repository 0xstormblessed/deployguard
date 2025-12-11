"""Tests for test coverage analyzer."""

import tempfile
from pathlib import Path

import pytest

from deployguard.models.testing import CoverageAnalysis, FoundryProject, ScriptTestCoverage
from deployguard.testing import (
    analyze_test_coverage,
    analyze_test_coverage_from_path,
    check_script_coverage,
    check_test_calls_run,
    find_imported_scripts,
    find_test_files,
    is_fork_test,
)


@pytest.fixture
def mock_foundry_project(tmp_path: Path) -> FoundryProject:
    """Create a mock Foundry project structure."""
    # Create foundry.toml
    foundry_toml = tmp_path / "foundry.toml"
    foundry_toml.write_text(
        """
[profile.default]
src = "src"
script = "script"
test = "test"
"""
    )

    # Create directories
    (tmp_path / "src").mkdir()
    (tmp_path / "script").mkdir()
    (tmp_path / "test").mkdir()

    # Create a deployment script
    deploy_script = tmp_path / "script" / "Deploy.s.sol"
    deploy_script.write_text(
        """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Script.sol";

contract Deploy is Script {
    function run() public {
        vm.startBroadcast();
        // Deployment logic
        vm.stopBroadcast();
    }
}
"""
    )

    # Create a test file
    test_file = tmp_path / "test" / "Deploy.t.sol"
    test_file.write_text(
        """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import "../script/Deploy.s.sol";

contract DeployTest is Test {
    Deploy deployer;

    function setUp() public {
        deployer = new Deploy();
    }

    function test_deployment() public {
        deployer.run();
        // Assertions
    }
}
"""
    )

    return FoundryProject.detect(tmp_path)


def test_foundry_project_detect(tmp_path: Path):
    """Test Foundry project detection."""
    # Create foundry.toml
    foundry_toml = tmp_path / "foundry.toml"
    foundry_toml.write_text("[profile.default]\n")

    project = FoundryProject.detect(tmp_path)
    assert project is not None
    assert project.root == tmp_path
    assert project.config_file == foundry_toml


def test_foundry_project_detect_no_config(tmp_path: Path):
    """Test Foundry project detection when no config exists."""
    project = FoundryProject.detect(tmp_path)
    assert project is None


def test_find_imported_scripts():
    """Test finding imported scripts from test content."""
    content = """
    import "../script/Deploy.s.sol";
    import {Upgrade} from "../script/Upgrade.s.sol";
    import "script/Migration.s.sol";
    """
    scripts = find_imported_scripts(content)
    assert "Deploy" in scripts
    assert "Upgrade" in scripts
    assert "Migration" in scripts


def test_check_test_calls_run():
    """Test detecting run() calls in test content."""
    # Test with run() call
    content_with_run = """
    function test_deployment() public {
        Deploy deployer = new Deploy();
        deployer.run();
    }
    """
    assert check_test_calls_run(content_with_run) is True

    # Test without run() call
    content_without_run = """
    function test_deployment() public {
        Deploy deployer = new Deploy();
        // No run() call
    }
    """
    assert check_test_calls_run(content_without_run) is False


def test_is_fork_test():
    """Test detecting fork tests."""
    # Test with fork
    content_with_fork = """
    contract DeployForkTest is Test {
        function setUp() public {
            vm.createSelectFork("mainnet");
        }
    }
    """
    assert is_fork_test(content_with_fork) is True

    # Test without fork
    content_without_fork = """
    contract DeployTest is Test {
        function setUp() public {
            // No fork
        }
    }
    """
    assert is_fork_test(content_without_fork) is False


def test_find_test_files(mock_foundry_project: FoundryProject):
    """Test finding test files for a deployment script."""
    deploy_script = mock_foundry_project.script_dir / "Deploy.s.sol"
    test_files = find_test_files(deploy_script, mock_foundry_project)

    assert len(test_files) == 1
    assert test_files[0].name == "Deploy.t.sol"


def test_check_script_coverage(mock_foundry_project: FoundryProject):
    """Test checking coverage for a single script."""
    deploy_script = mock_foundry_project.script_dir / "Deploy.s.sol"
    coverage = check_script_coverage(deploy_script, mock_foundry_project)

    assert isinstance(coverage, ScriptTestCoverage)
    assert coverage.deploy_script == deploy_script
    assert coverage.has_any_test is True
    assert len(coverage.test_files) > 0
    assert coverage.test_calls_run is True


def test_analyze_test_coverage(mock_foundry_project: FoundryProject):
    """Test analyzing test coverage for entire project."""
    analysis = analyze_test_coverage(mock_foundry_project)

    assert isinstance(analysis, CoverageAnalysis)
    assert analysis.project_root == mock_foundry_project.root
    assert len(analysis.deploy_scripts) == 1
    assert analysis.scripts_with_tests == 1
    assert analysis.scripts_without_tests == 0


def test_analyze_test_coverage_from_path(tmp_path: Path):
    """Test analyzing test coverage from a path."""
    # Create foundry.toml
    foundry_toml = tmp_path / "foundry.toml"
    foundry_toml.write_text("[profile.default]\n")

    (tmp_path / "script").mkdir()
    (tmp_path / "test").mkdir()

    # Create a deployment script
    deploy_script = tmp_path / "script" / "Deploy.s.sol"
    deploy_script.write_text("contract Deploy {}")

    analysis = analyze_test_coverage_from_path(tmp_path)

    assert analysis is not None
    assert isinstance(analysis, CoverageAnalysis)


def test_coverage_without_tests(tmp_path: Path):
    """Test coverage analysis for script without tests."""
    # Create foundry.toml
    foundry_toml = tmp_path / "foundry.toml"
    foundry_toml.write_text("[profile.default]\n")

    (tmp_path / "script").mkdir()
    (tmp_path / "test").mkdir()

    # Create a deployment script without tests
    deploy_script = tmp_path / "script" / "Untested.s.sol"
    deploy_script.write_text("contract Untested {}")

    project = FoundryProject.detect(tmp_path)
    analysis = analyze_test_coverage(project)

    assert analysis.scripts_with_tests == 0
    assert analysis.scripts_without_tests == 1


def test_fork_test_detection(tmp_path: Path):
    """Test detection of fork tests."""
    # Create foundry.toml
    foundry_toml = tmp_path / "foundry.toml"
    foundry_toml.write_text("[profile.default]\n")

    (tmp_path / "script").mkdir()
    (tmp_path / "test").mkdir()

    # Create a deployment script
    deploy_script = tmp_path / "script" / "Deploy.s.sol"
    deploy_script.write_text("contract Deploy {}")

    # Create a fork test
    fork_test = tmp_path / "test" / "Deploy.fork.t.sol"
    fork_test.write_text(
        """
contract DeployForkTest is Test {
    function setUp() public {
        vm.createSelectFork("mainnet");
    }
}
"""
    )

    project = FoundryProject.detect(tmp_path)
    coverage = check_script_coverage(deploy_script, project)

    assert coverage.has_fork_test is True
    assert len(coverage.fork_tests) > 0
