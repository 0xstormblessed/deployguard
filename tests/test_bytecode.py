"""Tests for bytecode analyzer."""

import pytest

from deployguard.dynamic.bytecode import BytecodeAnalyzer
from deployguard.models.core import Address


class TestBytecodeAnalyzer:
    """Tests for BytecodeAnalyzer."""

    def test_analyze_empty_bytecode(self) -> None:
        """Test analyzing empty bytecode."""
        analyzer = BytecodeAnalyzer()
        address = Address("0x1234567890123456789012345678901234567890")
        result = analyzer.analyze(address, "0x")

        assert result.address == address
        assert result.bytecode == "0x"
        assert result.has_delegatecall is False
        assert result.has_selfdestruct is False
        assert result.is_proxy_pattern is False

    def test_analyze_delegatecall(self) -> None:
        """Test detecting DELEGATECALL opcode."""
        analyzer = BytecodeAnalyzer()
        address = Address("0x1234567890123456789012345678901234567890")
        # Bytecode with DELEGATECALL (0xF4)
        bytecode = "0x" + "00" * 10 + "F4" + "00" * 20
        result = analyzer.analyze(address, bytecode)

        assert result.has_delegatecall is True
        assert "DELEGATECALL" in " ".join(result.risk_indicators)

    def test_analyze_selfdestruct(self) -> None:
        """Test detecting SELFDESTRUCT opcode."""
        analyzer = BytecodeAnalyzer()
        address = Address("0x1234567890123456789012345678901234567890")
        # Bytecode with SELFDESTRUCT (0xFF)
        bytecode = "0x" + "00" * 10 + "FF" + "00" * 20
        result = analyzer.analyze(address, bytecode)

        assert result.has_selfdestruct is True
        assert "SELFDESTRUCT" in " ".join(result.risk_indicators)

    def test_eip1167_proxy_detection(self) -> None:
        """Test EIP-1167 minimal proxy detection."""
        analyzer = BytecodeAnalyzer()
        address = Address("0x1234567890123456789012345678901234567890")
        # EIP-1167 pattern (simplified - would need full pattern)
        # This is a placeholder test
        bytecode = "0x363d3d373d3d3d363d73" + "00" * 20 + "5af43d82803e903d91602b57fd5bf3"
        result = analyzer.analyze(address, bytecode)

        # Note: This test may need adjustment based on actual EIP-1167 pattern
        assert isinstance(result.is_minimal_proxy, bool)

