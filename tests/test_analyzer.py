"""Tests for dynamic analyzer."""

import pytest
from unittest.mock import AsyncMock

from deployguard.dynamic.analyzer import DynamicAnalyzer
from deployguard.dynamic.rpc_client import RPCClient
from deployguard.models.core import Address
from deployguard.models.dynamic import ProxyVerification


@pytest.mark.asyncio
async def test_verify_proxy() -> None:
    """Test proxy verification."""
    # This would require mocking RPC client responses
    # Placeholder for now
    pass


@pytest.mark.asyncio
async def test_analyze_bytecode() -> None:
    """Test bytecode analysis."""
    rpc_client = RPCClient("https://eth-mainnet.g.alchemy.com/v2/test")
    analyzer = DynamicAnalyzer(rpc_client)

    address = Address("0x1234567890123456789012345678901234567890")
    bytecode = "0x6080604052348015600f57600080fd5b50"

    result = await analyzer.analyze_bytecode(address, bytecode)

    assert result.address == address
    assert result.bytecode == bytecode

    await rpc_client.close()

