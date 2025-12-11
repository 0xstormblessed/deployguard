"""Tests for RPC client."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp
import pytest

from deployguard.dynamic.rpc_client import RPCClient, RPCError
from deployguard.models.core import Address, Bytes32, StorageSlot


class MockPostContextManager:
    """Helper class to mock aiohttp's async context manager for post()."""

    def __init__(self, response):
        self.response = response

    async def __aenter__(self):
        return self.response

    async def __aexit__(self, *args):
        pass


@pytest.mark.asyncio
async def test_rpc_client_initialization() -> None:
    """Test RPC client initialization."""
    client = RPCClient("https://eth-mainnet.g.alchemy.com/v2/test")
    assert client.rpc_url == "https://eth-mainnet.g.alchemy.com/v2/test"
    assert client.timeout == 10
    assert client.retries == 3
    await client.close()


@pytest.mark.asyncio
async def test_rpc_client_custom_timeout_retries() -> None:
    """Test RPC client with custom timeout and retries."""
    client = RPCClient("https://eth-mainnet.g.alchemy.com/v2/test", timeout=30, retries=5)
    assert client.timeout == 30
    assert client.retries == 5
    await client.close()


@pytest.mark.asyncio
async def test_rpc_client_https_warning() -> None:
    """Test warning for non-HTTPS URLs."""
    with pytest.warns(UserWarning, match="HTTPS recommended"):
        client = RPCClient("http://localhost:8545")
        await client.close()


@pytest.mark.asyncio
async def test_rpc_client_context_manager() -> None:
    """Test RPC client async context manager."""
    async with RPCClient("https://eth-mainnet.g.alchemy.com/v2/test") as client:
        assert client.rpc_url == "https://eth-mainnet.g.alchemy.com/v2/test"


@pytest.mark.asyncio
async def test_get_storage_at_success() -> None:
    """Test successful storage slot query."""
    client = RPCClient("https://eth-mainnet.g.alchemy.com/v2/test")

    # Mock response
    mock_response = AsyncMock()
    mock_response.json = AsyncMock(
        return_value={
            "jsonrpc": "2.0",
            "id": 1,
            "result": "0x000000000000000000000000a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
        }
    )

    mock_session = MagicMock()
    mock_session.post = MagicMock(return_value=MockPostContextManager(mock_response))
    mock_session.close = AsyncMock()
    mock_session.closed = False

    client._session = mock_session

    proxy_address = Address("0x1234567890123456789012345678901234567890")
    slot = StorageSlot("0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc")

    result = await client.get_storage_at(proxy_address, slot)

    assert result.query.proxy_address == proxy_address
    assert result.query.slot == slot
    assert result.value == Bytes32(
        "0x000000000000000000000000a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
    )
    assert result.decoded_address == Address("0xa1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2")

    await client.close()


@pytest.mark.asyncio
async def test_get_storage_at_zero_value() -> None:
    """Test storage slot query with zero value."""
    client = RPCClient("https://eth-mainnet.g.alchemy.com/v2/test")

    # Mock response with zero value
    mock_response = AsyncMock()
    mock_response.json = AsyncMock(
        return_value={"jsonrpc": "2.0", "id": 1, "result": "0x" + "0" * 64}
    )

    mock_session = MagicMock()
    mock_session.post = MagicMock(return_value=MockPostContextManager(mock_response))
    mock_session.close = AsyncMock()
    mock_session.closed = False

    client._session = mock_session

    proxy_address = Address("0x1234567890123456789012345678901234567890")
    slot = StorageSlot("0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc")

    result = await client.get_storage_at(proxy_address, slot)

    assert result.decoded_address is None

    await client.close()


@pytest.mark.asyncio
async def test_get_code_success() -> None:
    """Test successful bytecode retrieval."""
    client = RPCClient("https://eth-mainnet.g.alchemy.com/v2/test")

    # Mock response with bytecode
    bytecode = "0x6080604052348015600f57600080fd5b50"
    mock_response = AsyncMock()
    mock_response.json = AsyncMock(
        return_value={"jsonrpc": "2.0", "id": 1, "result": bytecode}
    )

    mock_session = MagicMock()
    mock_session.post = MagicMock(return_value=MockPostContextManager(mock_response))
    mock_session.close = AsyncMock()
    mock_session.closed = False

    client._session = mock_session

    address = Address("0x1234567890123456789012345678901234567890")
    result = await client.get_code(address)

    assert result == bytecode

    await client.close()


@pytest.mark.asyncio
async def test_get_code_empty() -> None:
    """Test bytecode retrieval for EOA (empty code)."""
    client = RPCClient("https://eth-mainnet.g.alchemy.com/v2/test")

    # Mock response with empty bytecode
    mock_response = AsyncMock()
    mock_response.json = AsyncMock(return_value={"jsonrpc": "2.0", "id": 1, "result": "0x"})

    mock_session = MagicMock()
    mock_session.post = MagicMock(return_value=MockPostContextManager(mock_response))
    mock_session.close = AsyncMock()
    mock_session.closed = False

    client._session = mock_session

    address = Address("0x1234567890123456789012345678901234567890")
    result = await client.get_code(address)

    assert result == "0x"

    await client.close()


@pytest.mark.asyncio
async def test_get_block_number_success() -> None:
    """Test successful block number query."""
    client = RPCClient("https://eth-mainnet.g.alchemy.com/v2/test")

    # Mock response with block number
    mock_response = AsyncMock()
    mock_response.json = AsyncMock(
        return_value={"jsonrpc": "2.0", "id": 1, "result": "0x12345"}
    )

    mock_session = MagicMock()
    mock_session.post = MagicMock(return_value=MockPostContextManager(mock_response))
    mock_session.close = AsyncMock()
    mock_session.closed = False

    client._session = mock_session

    result = await client.get_block_number()

    assert result == 0x12345

    await client.close()


@pytest.mark.asyncio
async def test_rpc_error_handling() -> None:
    """Test RPC error handling."""
    client = RPCClient("https://eth-mainnet.g.alchemy.com/v2/test")

    # Mock RPC error response
    mock_response = AsyncMock()
    mock_response.json = AsyncMock(
        return_value={
            "jsonrpc": "2.0",
            "id": 1,
            "error": {"code": -32602, "message": "Invalid params"},
        }
    )

    mock_session = MagicMock()
    mock_session.post = MagicMock(return_value=MockPostContextManager(mock_response))
    mock_session.close = AsyncMock()
    mock_session.closed = False

    client._session = mock_session

    with pytest.raises(RPCError) as exc_info:
        await client.get_block_number()

    assert exc_info.value.code == -32602
    assert "Invalid params" in exc_info.value.message

    await client.close()


@pytest.mark.asyncio
async def test_rpc_retry_on_timeout() -> None:
    """Test retry logic on timeout."""
    client = RPCClient("https://eth-mainnet.g.alchemy.com/v2/test", retries=3)

    # Mock timeout then success
    mock_response_success = AsyncMock()
    mock_response_success.json = AsyncMock(
        return_value={"jsonrpc": "2.0", "id": 1, "result": "0x12345"}
    )

    call_count = 0

    def mock_post(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        if call_count < 2:
            raise asyncio.TimeoutError()
        return MockPostContextManager(mock_response_success)

    mock_session = MagicMock()
    mock_session.post = mock_post
    mock_session.close = AsyncMock()
    mock_session.closed = False

    client._session = mock_session

    result = await client.get_block_number()

    assert result == 0x12345
    assert call_count == 2  # Failed once, succeeded on retry

    await client.close()


@pytest.mark.asyncio
async def test_rpc_retry_exhausted() -> None:
    """Test retry logic exhaustion."""
    client = RPCClient("https://eth-mainnet.g.alchemy.com/v2/test", retries=2)

    # Mock persistent timeout
    def mock_post(*args, **kwargs):
        raise asyncio.TimeoutError()

    mock_session = MagicMock()
    mock_session.post = mock_post
    mock_session.close = AsyncMock()
    mock_session.closed = False

    client._session = mock_session

    with pytest.raises(asyncio.TimeoutError):
        await client.get_block_number()

    await client.close()


@pytest.mark.asyncio
async def test_get_storage_at_with_block_number() -> None:
    """Test storage slot query at specific block."""
    client = RPCClient("https://eth-mainnet.g.alchemy.com/v2/test")

    # Track request params (only capture getStorageAt params)
    request_params = None

    def mock_post(url, json=None):
        nonlocal request_params
        mock_response = AsyncMock()
        if json and json.get("method") == "eth_getStorageAt":
            # Capture params only for getStorageAt
            request_params = json.get("params") if json else None
            mock_response.json = AsyncMock(
                return_value={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": "0x" + "0" * 64,
                }
            )
        elif json and json.get("method") == "eth_blockNumber":
            mock_response.json = AsyncMock(
                return_value={"jsonrpc": "2.0", "id": 1, "result": "0x1000"}
            )
        return MockPostContextManager(mock_response)

    mock_session = MagicMock()
    mock_session.post = mock_post
    mock_session.close = AsyncMock()
    mock_session.closed = False

    client._session = mock_session

    proxy_address = Address("0x1234567890123456789012345678901234567890")
    slot = StorageSlot("0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc")
    block_num = 100

    await client.get_storage_at(proxy_address, slot, block=block_num)

    # Verify block number was passed correctly
    assert request_params is not None
    assert request_params[2] == hex(block_num)

    await client.close()

