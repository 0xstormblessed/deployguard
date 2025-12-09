"""Tests for static analysis models."""

import pytest

from deployguard.models.core import SourceLocation
from deployguard.models.static import (
    BoundaryType,
    ProxyDeployment,
    ProxyType,
    ScriptAnalysis,
    ScriptType,
    TransactionBoundary,
    VariableInfo,
)


class TestProxyType:
    """Tests for ProxyType enum."""

    def test_proxy_types(self) -> None:
        """Test proxy type values."""
        assert ProxyType.ERC1967_PROXY.value == "ERC1967Proxy"
        assert ProxyType.TRANSPARENT_UPGRADEABLE_PROXY.value == "TransparentUpgradeableProxy"


class TestVariableInfo:
    """Tests for VariableInfo model."""

    def test_create_variable_info(self) -> None:
        """Test creating variable info."""
        loc = SourceLocation(file_path="test.sol", line_number=5)
        var_info = VariableInfo(
            name="impl",
            assigned_value="0x1234...",
            assignment_location=loc,
            is_hardcoded=True,
        )
        assert var_info.name == "impl"
        assert var_info.is_hardcoded is True


class TestTransactionBoundary:
    """Tests for TransactionBoundary model."""

    def test_create_transaction_boundary(self) -> None:
        """Test creating transaction boundary."""
        loc = SourceLocation(file_path="test.sol", line_number=10)
        boundary = TransactionBoundary(
            boundary_type=BoundaryType.VM_START_BROADCAST,
            location=loc,
            scope_start=10,
            scope_end=20,
        )
        assert boundary.boundary_type == BoundaryType.VM_START_BROADCAST
        assert boundary.scope_start == 10
        assert boundary.scope_end == 20


class TestProxyDeployment:
    """Tests for ProxyDeployment model."""

    def test_create_proxy_deployment(self) -> None:
        """Test creating proxy deployment."""
        loc = SourceLocation(file_path="script/Deploy.s.sol", line_number=15)
        deployment = ProxyDeployment(
            proxy_type=ProxyType.ERC1967_PROXY,
            implementation_arg="impl",
            init_data_arg="",
            location=loc,
            has_empty_init=True,
            is_atomic=False,
        )
        assert deployment.proxy_type == ProxyType.ERC1967_PROXY
        assert deployment.has_empty_init is True
        assert deployment.is_atomic is False


class TestScriptAnalysis:
    """Tests for ScriptAnalysis model."""

    def test_create_script_analysis(self) -> None:
        """Test creating script analysis."""
        analysis = ScriptAnalysis(
            file_path="script/Deploy.s.sol",
            script_type=ScriptType.FOUNDRY,
        )
        assert analysis.file_path == "script/Deploy.s.sol"
        assert analysis.script_type == ScriptType.FOUNDRY
        assert len(analysis.proxy_deployments) == 0
        assert len(analysis.tx_boundaries) == 0
        assert analysis.has_private_key_env is False
        assert analysis.has_ownership_transfer is False

    def test_script_analysis_with_deployments(self) -> None:
        """Test script analysis with proxy deployments."""
        loc = SourceLocation(file_path="script/Deploy.s.sol", line_number=15)
        deployment = ProxyDeployment(
            proxy_type=ProxyType.ERC1967_PROXY,
            implementation_arg="impl",
            init_data_arg="",
            location=loc,
        )
        analysis = ScriptAnalysis(
            file_path="script/Deploy.s.sol",
            script_type=ScriptType.FOUNDRY,
            proxy_deployments=[deployment],
        )
        assert len(analysis.proxy_deployments) == 1
        assert analysis.proxy_deployments[0] == deployment

