"""Integration tests for end-to-end dynamic analysis."""

from unittest.mock import AsyncMock, patch

import pytest

from deployguard.constants import EIP1967_ADMIN_SLOT, EIP1967_IMPLEMENTATION_SLOT
from deployguard.dynamic.analyzer import verify_proxy
from deployguard.models.core import Address, Bytes32, StorageSlot
from deployguard.models.dynamic import StorageSlotQuery, StorageSlotResult
from deployguard.models.report import AnalysisType


@pytest.mark.asyncio
async def test_full_proxy_verification_no_issues() -> None:
    """Test end-to-end proxy verification with no issues."""
    mock_rpc = AsyncMock()

    proxy_addr = Address("0x1234567890123456789012345678901234567890")
    impl_addr = Address("0xa1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2")
    admin_addr = Address("0xb1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2")

    # Mock implementation slot
    impl_slot_result = StorageSlotResult(
        query=StorageSlotQuery(
            proxy_address=proxy_addr,
            slot=StorageSlot(EIP1967_IMPLEMENTATION_SLOT),
        ),
        value=Bytes32("0x000000000000000000000000a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"),
        decoded_address=impl_addr,
        block_number=1000,
    )

    # Mock admin slot
    admin_slot_result = StorageSlotResult(
        query=StorageSlotQuery(
            proxy_address=proxy_addr,
            slot=StorageSlot(EIP1967_ADMIN_SLOT),
        ),
        value=Bytes32("0x000000000000000000000000b1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"),
        decoded_address=admin_addr,
        block_number=1000,
    )

    # Mock bytecode (no DELEGATECALL)
    proxy_bytecode = "0x363d3d373d3d3d363d73"
    impl_bytecode = "0x6080604052348015600f57600080fd5b50"

    mock_rpc.get_storage_at = AsyncMock(side_effect=[impl_slot_result, admin_slot_result])
    mock_rpc.get_code = AsyncMock(side_effect=[proxy_bytecode, impl_bytecode])
    mock_rpc.__aenter__ = AsyncMock(return_value=mock_rpc)
    mock_rpc.__aexit__ = AsyncMock(return_value=None)

    with patch("deployguard.dynamic.analyzer.RPCClient", return_value=mock_rpc):
        report = await verify_proxy(
            proxy_addr,
            impl_addr,
            "https://eth-mainnet.g.alchemy.com/v2/test",
            expected_admin=admin_addr,
        )

    # Assertions
    assert report.analysis_type == AnalysisType.DYNAMIC
    assert report.target_addresses == [proxy_addr]
    assert report.summary.total_findings == 0
    assert report.summary.critical_count == 0
    assert report.summary.high_count == 0
    assert report.summary.contracts_verified == 1
    assert report.summary.rules_executed == 5
    assert report.exit_code == 0
    assert report.summary.passed is True


@pytest.mark.asyncio
async def test_full_proxy_verification_implementation_mismatch() -> None:
    """Test end-to-end proxy verification with implementation mismatch (IMPL_MISMATCH)."""
    mock_rpc = AsyncMock()

    proxy_addr = Address("0x1234567890123456789012345678901234567890")
    expected_impl = Address("0xa1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2")
    actual_impl = Address("0xdifferent0000000000000000000000000000000")

    # Mock implementation slot with wrong address
    impl_slot_result = StorageSlotResult(
        query=StorageSlotQuery(
            proxy_address=proxy_addr,
            slot=StorageSlot(EIP1967_IMPLEMENTATION_SLOT),
        ),
        value=Bytes32("0x000000000000000000000000different0000000000000000000000000000000"),
        decoded_address=actual_impl,
        block_number=1000,
    )

    proxy_bytecode = "0x363d3d373d3d3d363d73"
    impl_bytecode = "0x6080604052348015600f57600080fd5b50"

    mock_rpc.get_storage_at = AsyncMock(return_value=impl_slot_result)
    mock_rpc.get_code = AsyncMock(side_effect=[proxy_bytecode, impl_bytecode])
    mock_rpc.__aenter__ = AsyncMock(return_value=mock_rpc)
    mock_rpc.__aexit__ = AsyncMock(return_value=None)

    with patch("deployguard.dynamic.analyzer.RPCClient", return_value=mock_rpc):
        report = await verify_proxy(
            proxy_addr,
            expected_impl,
            "https://eth-mainnet.g.alchemy.com/v2/test",
        )

    # Should have IMPL_MISMATCH violation
    assert report.summary.total_findings >= 1
    assert report.summary.critical_count >= 1
    assert report.exit_code == 1
    assert report.summary.passed is False

    # Find IMPL_MISMATCH finding
    dg101_findings = [f for f in report.findings if f.rule_id == "IMPL_MISMATCH"]
    assert len(dg101_findings) == 1
    finding = dg101_findings[0]
    assert finding.severity.value == "critical"
    assert expected_impl in finding.description
    assert actual_impl in finding.description


@pytest.mark.asyncio
async def test_full_proxy_verification_uninitialized() -> None:
    """Test end-to-end proxy verification with uninitialized proxy (UNINITIALIZED_PROXY)."""
    mock_rpc = AsyncMock()

    proxy_addr = Address("0x1234567890123456789012345678901234567890")
    expected_impl = Address("0xa1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2")

    # Mock empty implementation slot
    impl_slot_result = StorageSlotResult(
        query=StorageSlotQuery(
            proxy_address=proxy_addr,
            slot=StorageSlot(EIP1967_IMPLEMENTATION_SLOT),
        ),
        value=Bytes32("0x" + "0" * 64),
        decoded_address=None,
        block_number=1000,
    )

    proxy_bytecode = "0x363d3d373d3d3d363d73"

    mock_rpc.get_storage_at = AsyncMock(return_value=impl_slot_result)
    mock_rpc.get_code = AsyncMock(return_value=proxy_bytecode)
    mock_rpc.__aenter__ = AsyncMock(return_value=mock_rpc)
    mock_rpc.__aexit__ = AsyncMock(return_value=None)

    with patch("deployguard.dynamic.analyzer.RPCClient", return_value=mock_rpc):
        report = await verify_proxy(
            proxy_addr,
            expected_impl,
            "https://eth-mainnet.g.alchemy.com/v2/test",
        )

    # Should have UNINITIALIZED_PROXY violation
    assert report.summary.total_findings >= 1
    assert report.summary.high_count >= 1
    assert report.exit_code == 1

    # Find UNINITIALIZED_PROXY finding
    dg103_findings = [f for f in report.findings if f.rule_id == "UNINITIALIZED_PROXY"]
    assert len(dg103_findings) == 1
    finding = dg103_findings[0]
    assert finding.severity.value == "high"
    assert "uninitialized" in finding.description.lower()


@pytest.mark.asyncio
async def test_full_proxy_verification_shadow_contract() -> None:
    """Test end-to-end proxy verification with shadow contract (SHADOW_CONTRACT)."""
    mock_rpc = AsyncMock()

    proxy_addr = Address("0x1234567890123456789012345678901234567890")
    impl_addr = Address("0xa1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2")

    # Mock implementation slot
    impl_slot_result = StorageSlotResult(
        query=StorageSlotQuery(
            proxy_address=proxy_addr,
            slot=StorageSlot(EIP1967_IMPLEMENTATION_SLOT),
        ),
        value=Bytes32("0x000000000000000000000000a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"),
        decoded_address=impl_addr,
        block_number=1000,
    )

    proxy_bytecode = "0x363d3d373d3d3d363d73"
    # Implementation bytecode with DELEGATECALL (0xF4)
    impl_bytecode = "0x6080604052348015600f57600080fd5b50F4"

    mock_rpc.get_storage_at = AsyncMock(return_value=impl_slot_result)
    mock_rpc.get_code = AsyncMock(side_effect=[proxy_bytecode, impl_bytecode])
    mock_rpc.__aenter__ = AsyncMock(return_value=mock_rpc)
    mock_rpc.__aexit__ = AsyncMock(return_value=None)

    with patch("deployguard.dynamic.analyzer.RPCClient", return_value=mock_rpc):
        report = await verify_proxy(
            proxy_addr,
            impl_addr,
            "https://eth-mainnet.g.alchemy.com/v2/test",
        )

    # Should have SHADOW_CONTRACT violation
    assert report.summary.total_findings >= 1
    assert report.summary.high_count >= 1
    assert report.exit_code == 1

    # Find SHADOW_CONTRACT finding
    dg102_findings = [f for f in report.findings if f.rule_id == "SHADOW_CONTRACT"]
    assert len(dg102_findings) == 1
    finding = dg102_findings[0]
    assert finding.severity.value == "high"
    assert "shadow" in finding.description.lower()


@pytest.mark.asyncio
async def test_full_proxy_verification_admin_mismatch() -> None:
    """Test end-to-end proxy verification with admin mismatch (ADMIN_MISMATCH)."""
    mock_rpc = AsyncMock()

    proxy_addr = Address("0x1234567890123456789012345678901234567890")
    impl_addr = Address("0xa1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2")
    expected_admin = Address("0xb1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2")
    actual_admin = Address("0xdifferent0000000000000000000000000000000")

    # Mock implementation slot
    impl_slot_result = StorageSlotResult(
        query=StorageSlotQuery(
            proxy_address=proxy_addr,
            slot=StorageSlot(EIP1967_IMPLEMENTATION_SLOT),
        ),
        value=Bytes32("0x000000000000000000000000a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"),
        decoded_address=impl_addr,
        block_number=1000,
    )

    # Mock admin slot with wrong address
    admin_slot_result = StorageSlotResult(
        query=StorageSlotQuery(
            proxy_address=proxy_addr,
            slot=StorageSlot(EIP1967_ADMIN_SLOT),
        ),
        value=Bytes32("0x000000000000000000000000different0000000000000000000000000000000"),
        decoded_address=actual_admin,
        block_number=1000,
    )

    proxy_bytecode = "0x363d3d373d3d3d363d73"
    impl_bytecode = "0x6080604052348015600f57600080fd5b50"

    mock_rpc.get_storage_at = AsyncMock(side_effect=[impl_slot_result, admin_slot_result])
    mock_rpc.get_code = AsyncMock(side_effect=[proxy_bytecode, impl_bytecode])
    mock_rpc.__aenter__ = AsyncMock(return_value=mock_rpc)
    mock_rpc.__aexit__ = AsyncMock(return_value=None)

    with patch("deployguard.dynamic.analyzer.RPCClient", return_value=mock_rpc):
        report = await verify_proxy(
            proxy_addr,
            impl_addr,
            "https://eth-mainnet.g.alchemy.com/v2/test",
            expected_admin=expected_admin,
        )

    # Should have ADMIN_MISMATCH violation
    assert report.summary.total_findings >= 1
    assert report.summary.medium_count >= 1

    # Find ADMIN_MISMATCH finding
    dg104_findings = [f for f in report.findings if f.rule_id == "ADMIN_MISMATCH"]
    assert len(dg104_findings) == 1
    finding = dg104_findings[0]
    assert finding.severity.value == "medium"
    assert "admin" in finding.description.lower()


@pytest.mark.asyncio
async def test_full_proxy_verification_multiple_issues() -> None:
    """Test end-to-end proxy verification with multiple issues."""
    mock_rpc = AsyncMock()

    proxy_addr = Address("0x1234567890123456789012345678901234567890")
    expected_impl = Address("0xa1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2")
    actual_impl = Address("0xdifferent0000000000000000000000000000000")
    expected_admin = Address("0xb1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2")
    actual_admin = Address("0xadmindiff0000000000000000000000000000")

    # Mock implementation slot with wrong address
    impl_slot_result = StorageSlotResult(
        query=StorageSlotQuery(
            proxy_address=proxy_addr,
            slot=StorageSlot(EIP1967_IMPLEMENTATION_SLOT),
        ),
        value=Bytes32("0x000000000000000000000000different0000000000000000000000000000000"),
        decoded_address=actual_impl,
        block_number=1000,
    )

    # Mock admin slot with wrong address
    admin_slot_result = StorageSlotResult(
        query=StorageSlotQuery(
            proxy_address=proxy_addr,
            slot=StorageSlot(EIP1967_ADMIN_SLOT),
        ),
        value=Bytes32("0x000000000000000000000000admindiff0000000000000000000000000000"),
        decoded_address=actual_admin,
        block_number=1000,
    )

    proxy_bytecode = "0x363d3d373d3d3d363d73"
    # Implementation with DELEGATECALL (shadow contract)
    impl_bytecode = "0x6080604052348015600f57600080fd5b50F4"

    mock_rpc.get_storage_at = AsyncMock(side_effect=[impl_slot_result, admin_slot_result])
    mock_rpc.get_code = AsyncMock(side_effect=[proxy_bytecode, impl_bytecode])
    mock_rpc.__aenter__ = AsyncMock(return_value=mock_rpc)
    mock_rpc.__aexit__ = AsyncMock(return_value=None)

    with patch("deployguard.dynamic.analyzer.RPCClient", return_value=mock_rpc):
        report = await verify_proxy(
            proxy_addr,
            expected_impl,
            "https://eth-mainnet.g.alchemy.com/v2/test",
            expected_admin=expected_admin,
        )

    # Should have multiple violations
    assert report.summary.total_findings >= 3
    assert report.summary.critical_count >= 1  # IMPL_MISMATCH
    assert report.summary.high_count >= 1  # SHADOW_CONTRACT
    assert report.summary.medium_count >= 1  # ADMIN_MISMATCH
    assert report.exit_code == 1

    # Verify all expected findings
    rule_ids = {f.rule_id for f in report.findings}
    assert "IMPL_MISMATCH" in rule_ids  # Implementation mismatch
    assert "SHADOW_CONTRACT" in rule_ids  # Shadow contract
    assert "ADMIN_MISMATCH" in rule_ids  # Admin mismatch


@pytest.mark.asyncio
async def test_rpc_url_redaction() -> None:
    """Test that RPC URL is redacted in report."""
    mock_rpc = AsyncMock()

    proxy_addr = Address("0x1234567890123456789012345678901234567890")
    impl_addr = Address("0xa1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2")

    impl_slot_result = StorageSlotResult(
        query=StorageSlotQuery(
            proxy_address=proxy_addr,
            slot=StorageSlot(EIP1967_IMPLEMENTATION_SLOT),
        ),
        value=Bytes32("0x000000000000000000000000a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"),
        decoded_address=impl_addr,
        block_number=1000,
    )

    mock_rpc.get_storage_at = AsyncMock(return_value=impl_slot_result)
    mock_rpc.get_code = AsyncMock(side_effect=["0x363d3d", "0x6080"])
    mock_rpc.__aenter__ = AsyncMock(return_value=mock_rpc)
    mock_rpc.__aexit__ = AsyncMock(return_value=None)

    sensitive_url = "https://user:password@eth-mainnet.g.alchemy.com:443/v2/secret-key"

    with patch("deployguard.dynamic.analyzer.RPCClient", return_value=mock_rpc):
        report = await verify_proxy(proxy_addr, impl_addr, sensitive_url)

    # RPC URL should be redacted (no credentials or API keys)
    assert report.rpc_url is not None
    assert "password" not in report.rpc_url
    assert "secret-key" not in report.rpc_url
    assert "https://" in report.rpc_url
