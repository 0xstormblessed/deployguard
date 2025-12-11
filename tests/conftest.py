"""Pytest configuration and fixtures."""

from pathlib import Path
import pytest


@pytest.fixture
def sample_address() -> str:
    """Sample Ethereum address for testing."""
    return "0x1234567890123456789012345678901234567890"


@pytest.fixture
def sample_bytes32() -> str:
    """Sample bytes32 value for testing."""
    return "0x" + "0" * 64


@pytest.fixture
def foundry_project_path(tmp_path: Path) -> Path:
    """Create a temporary Foundry project structure for testing."""
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

    # Create a sample deployment script
    deploy_script = tmp_path / "script" / "Deploy.s.sol"
    deploy_script.write_text(
        """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Script.sol";

contract DeployScript is Script {
    function run() public {
        vm.startBroadcast();
        // Deploy logic here
        vm.stopBroadcast();
    }
}
"""
    )

    return tmp_path

