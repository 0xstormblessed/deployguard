"""Tests for dynamic analyzer."""

from unittest.mock import AsyncMock, patch

import pytest

from deployguard.constants import EIP1967_IMPLEMENTATION_SLOT
from deployguard.dynamic.analyzer import (
    DynamicAnalyzer,
    get_implementation_address,
    quick_check,
    verify_proxy,
)
from deployguard.dynamic.rpc_client import RPCClient
from deployguard.models.core import Address, Bytes32, StorageSlot
from deployguard.models.dynamic import (
    ProxyStandard,
    ProxyVerification,
    StorageSlotQuery,
    StorageSlotResult,
)


@pytest.mark.asyncio
async def test_verify_proxy_initialized() -> None:
    """Test proxy verification for initialized proxy."""
    # Create mock RPC client
    mock_rpc = AsyncMock(spec=RPCClient)

    # Mock implementation slot result
    impl_address = Address("0xa1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2")
    impl_slot_result = StorageSlotResult(
        query=StorageSlotQuery(
            proxy_address=Address("0x1234567890123456789012345678901234567890"),
            slot=StorageSlot(EIP1967_IMPLEMENTATION_SLOT),
        ),
        value=Bytes32("0x000000000000000000000000a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"),
        decoded_address=impl_address,
        block_number=1000,
    )

    # Mock bytecode responses
    proxy_bytecode = "0x363d3d373d3d3d363d73"
    impl_bytecode = "0x6080604052348015600f57600080fd5b50"

    mock_rpc.get_storage_at = AsyncMock(return_value=impl_slot_result)
    mock_rpc.get_code = AsyncMock(side_effect=[proxy_bytecode, impl_bytecode])

    analyzer = DynamicAnalyzer(mock_rpc)

    verification = ProxyVerification(
        proxy_address=Address("0x1234567890123456789012345678901234567890"),
        expected_implementation=impl_address,
        rpc_url="https://eth-mainnet.g.alchemy.com/v2/test",
    )

    proxy_state = await analyzer.verify_proxy(verification)

    assert proxy_state.proxy_address == verification.proxy_address
    assert proxy_state.implementation_slot.decoded_address == impl_address
    assert proxy_state.is_initialized is True
    assert proxy_state.proxy_standard == ProxyStandard.EIP_1967
    assert proxy_state.proxy_bytecode == proxy_bytecode
    assert proxy_state.implementation_bytecode == impl_bytecode


@pytest.mark.asyncio
async def test_verify_proxy_uninitialized() -> None:
    """Test proxy verification for uninitialized proxy."""
    # Create mock RPC client
    mock_rpc = AsyncMock(spec=RPCClient)

    # Mock empty implementation slot
    impl_slot_result = StorageSlotResult(
        query=StorageSlotQuery(
            proxy_address=Address("0x1234567890123456789012345678901234567890"),
            slot=StorageSlot(EIP1967_IMPLEMENTATION_SLOT),
        ),
        value=Bytes32("0x" + "0" * 64),
        decoded_address=None,
        block_number=1000,
    )

    proxy_bytecode = "0x363d3d373d3d3d363d73"

    mock_rpc.get_storage_at = AsyncMock(return_value=impl_slot_result)
    mock_rpc.get_code = AsyncMock(return_value=proxy_bytecode)

    analyzer = DynamicAnalyzer(mock_rpc)

    verification = ProxyVerification(
        proxy_address=Address("0x1234567890123456789012345678901234567890"),
        expected_implementation=Address("0xa1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"),
        rpc_url="https://eth-mainnet.g.alchemy.com/v2/test",
    )

    proxy_state = await analyzer.verify_proxy(verification)

    assert proxy_state.is_initialized is False
    assert proxy_state.proxy_standard == ProxyStandard.UNKNOWN
    assert proxy_state.implementation_bytecode is None


@pytest.mark.asyncio
async def test_verify_proxy_with_admin() -> None:
    """Test proxy verification with admin slot."""
    # Create mock RPC client
    mock_rpc = AsyncMock(spec=RPCClient)

    impl_address = Address("0xa1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2")
    admin_address = Address("0xb1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2")

    impl_slot_result = StorageSlotResult(
        query=StorageSlotQuery(
            proxy_address=Address("0x1234567890123456789012345678901234567890"),
            slot=StorageSlot(EIP1967_IMPLEMENTATION_SLOT),
        ),
        value=Bytes32("0x000000000000000000000000a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"),
        decoded_address=impl_address,
        block_number=1000,
    )

    admin_slot_result = StorageSlotResult(
        query=StorageSlotQuery(
            proxy_address=Address("0x1234567890123456789012345678901234567890"),
            slot=StorageSlot("0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"),
        ),
        value=Bytes32("0x000000000000000000000000b1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"),
        decoded_address=admin_address,
        block_number=1000,
    )

    proxy_bytecode = "0x363d3d373d3d3d363d73"
    impl_bytecode = "0x6080604052348015600f57600080fd5b50"

    mock_rpc.get_storage_at = AsyncMock(side_effect=[impl_slot_result, admin_slot_result])
    mock_rpc.get_code = AsyncMock(side_effect=[proxy_bytecode, impl_bytecode])

    analyzer = DynamicAnalyzer(mock_rpc)

    verification = ProxyVerification(
        proxy_address=Address("0x1234567890123456789012345678901234567890"),
        expected_implementation=impl_address,
        rpc_url="https://eth-mainnet.g.alchemy.com/v2/test",
        expected_admin=admin_address,
    )

    proxy_state = await analyzer.verify_proxy(verification)

    assert proxy_state.admin_slot is not None
    assert proxy_state.admin_slot.decoded_address == admin_address


@pytest.mark.asyncio
async def test_analyze_bytecode() -> None:
    """Test bytecode analysis."""
    mock_rpc = AsyncMock(spec=RPCClient)
    analyzer = DynamicAnalyzer(mock_rpc)

    address = Address("0x1234567890123456789012345678901234567890")
    # Bytecode with DELEGATECALL (0xF4)
    bytecode = "0x6080604052348015600f57600080fd5b50F4"

    result = await analyzer.analyze_bytecode(address, bytecode)

    assert result.address == address
    assert result.bytecode == bytecode
    assert result.has_delegatecall is True


@pytest.mark.asyncio
async def test_quick_check_match() -> None:
    """Test quick_check with matching implementation."""
    # Create mock RPC client
    mock_rpc = AsyncMock(spec=RPCClient)

    impl_address = Address("0xa1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2")

    impl_slot_result = StorageSlotResult(
        query=StorageSlotQuery(
            proxy_address=Address("0x1234567890123456789012345678901234567890"),
            slot=StorageSlot(EIP1967_IMPLEMENTATION_SLOT),
        ),
        value=Bytes32("0x000000000000000000000000a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"),
        decoded_address=impl_address,
        block_number=1000,
    )

    mock_rpc.get_storage_at = AsyncMock(return_value=impl_slot_result)
    mock_rpc.get_code = AsyncMock(return_value="0x6080")
    mock_rpc.__aenter__ = AsyncMock(return_value=mock_rpc)
    mock_rpc.__aexit__ = AsyncMock(return_value=None)

    # Patch RPCClient constructor
    with patch(
        "deployguard.dynamic.analyzer.RPCClient", return_value=mock_rpc
    ):
        result = await quick_check(
            Address("0x1234567890123456789012345678901234567890"),
            impl_address,
            "https://eth-mainnet.g.alchemy.com/v2/test",
        )

    assert result is True


@pytest.mark.asyncio
async def test_quick_check_mismatch() -> None:
    """Test quick_check with mismatched implementation."""
    mock_rpc = AsyncMock(spec=RPCClient)

    impl_slot_result = StorageSlotResult(
        query=StorageSlotQuery(
            proxy_address=Address("0x1234567890123456789012345678901234567890"),
            slot=StorageSlot(EIP1967_IMPLEMENTATION_SLOT),
        ),
        value=Bytes32("0x000000000000000000000000a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"),
        decoded_address=Address("0xa1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"),
        block_number=1000,
    )

    mock_rpc.get_storage_at = AsyncMock(return_value=impl_slot_result)
    mock_rpc.get_code = AsyncMock(return_value="0x6080")
    mock_rpc.__aenter__ = AsyncMock(return_value=mock_rpc)
    mock_rpc.__aexit__ = AsyncMock(return_value=None)

    with patch(
        "deployguard.dynamic.analyzer.RPCClient", return_value=mock_rpc
    ):
        result = await quick_check(
            Address("0x1234567890123456789012345678901234567890"),
            Address("0xdifferent0000000000000000000000000000000"),
            "https://eth-mainnet.g.alchemy.com/v2/test",
        )

    assert result is False


@pytest.mark.asyncio
async def test_get_implementation_address() -> None:
    """Test get_implementation_address helper."""
    mock_rpc = AsyncMock(spec=RPCClient)

    impl_address = Address("0xa1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2")

    impl_slot_result = StorageSlotResult(
        query=StorageSlotQuery(
            proxy_address=Address("0x1234567890123456789012345678901234567890"),
            slot=StorageSlot(EIP1967_IMPLEMENTATION_SLOT),
        ),
        value=Bytes32("0x000000000000000000000000a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"),
        decoded_address=impl_address,
        block_number=1000,
    )

    mock_rpc.get_storage_at = AsyncMock(return_value=impl_slot_result)
    mock_rpc.__aenter__ = AsyncMock(return_value=mock_rpc)
    mock_rpc.__aexit__ = AsyncMock(return_value=None)

    with patch(
        "deployguard.dynamic.analyzer.RPCClient", return_value=mock_rpc
    ):
        result = await get_implementation_address(
            Address("0x1234567890123456789012345678901234567890"),
            "https://eth-mainnet.g.alchemy.com/v2/test",
        )

    assert result == impl_address


@pytest.mark.asyncio
async def test_verify_proxy_full_report() -> None:
    """Test verify_proxy function that generates full report."""
    mock_rpc = AsyncMock(spec=RPCClient)

    impl_address = Address("0xa1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2")

    impl_slot_result = StorageSlotResult(
        query=StorageSlotQuery(
            proxy_address=Address("0x1234567890123456789012345678901234567890"),
            slot=StorageSlot(EIP1967_IMPLEMENTATION_SLOT),
        ),
        value=Bytes32("0x000000000000000000000000a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"),
        decoded_address=impl_address,
        block_number=1000,
    )

    proxy_bytecode = "0x363d3d373d3d3d363d73"
    impl_bytecode = "0x6080604052348015600f57600080fd5b50"

    mock_rpc.get_storage_at = AsyncMock(return_value=impl_slot_result)
    mock_rpc.get_code = AsyncMock(side_effect=[proxy_bytecode, impl_bytecode])
    mock_rpc.__aenter__ = AsyncMock(return_value=mock_rpc)
    mock_rpc.__aexit__ = AsyncMock(return_value=None)

    with patch(
        "deployguard.dynamic.analyzer.RPCClient", return_value=mock_rpc
    ):
        report = await verify_proxy(
            Address("0x1234567890123456789012345678901234567890"),
            impl_address,
            "https://eth-mainnet.g.alchemy.com/v2/test",
        )

    assert report.report_id is not None
    assert report.target_addresses == [Address("0x1234567890123456789012345678901234567890")]
    assert report.summary.contracts_verified == 1
    assert report.summary.rules_executed == 5

