"""RPC client for Ethereum JSON-RPC interactions."""

import asyncio
import warnings
from urllib.parse import urlparse

import aiohttp

from deployguard.models.core import Address, Bytes32, StorageSlot
from deployguard.models.dynamic import StorageSlotQuery, StorageSlotResult


class RPCError(Exception):
    """RPC request error."""

    def __init__(self, code: int, message: str, data: dict | None = None):
        """Initialize RPC error.

        Args:
            code: RPC error code
            message: Error message
            data: Optional error data
        """
        self.code = code
        self.message = message
        self.data = data
        super().__init__(f"RPC Error {code}: {message}")


class RPCClient:
    """Client for Ethereum JSON-RPC interactions.

    This client handles all RPC calls needed for dynamic analysis:
    - Storage slot queries (eth_getStorageAt)
    - Bytecode retrieval (eth_getCode)
    - Block number queries (eth_blockNumber)

    Attributes:
        rpc_url: RPC endpoint URL
        timeout: Request timeout in seconds
        retries: Number of retry attempts
    """

    def __init__(self, rpc_url: str, timeout: int = 10, retries: int = 3):
        """Initialize RPC client.

        Args:
            rpc_url: RPC endpoint URL (HTTPS recommended)
            timeout: Request timeout in seconds
            retries: Number of retry attempts
        """
        self.rpc_url = rpc_url
        self.timeout = timeout
        self.retries = retries
        self._validate_url()
        self._session: aiohttp.ClientSession | None = None

    def _validate_url(self) -> None:
        """Validate RPC URL is HTTPS."""
        parsed = urlparse(self.rpc_url)
        if parsed.scheme != "https":
            warnings.warn(
                f"RPC URL uses {parsed.scheme}, HTTPS recommended for security",
                UserWarning,
                stacklevel=2,
            )

    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create aiohttp session."""
        if self._session is None or self._session.closed:
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            self._session = aiohttp.ClientSession(timeout=timeout)
        return self._session

    async def _request(self, method: str, params: list, request_id: int = 1) -> dict:
        """Make JSON-RPC request with retry logic.

        Args:
            method: RPC method name
            params: RPC method parameters
            request_id: Request ID for JSON-RPC

        Returns:
            RPC response result

        Raises:
            RPCError: If RPC request fails
            aiohttp.ClientError: If HTTP request fails
        """
        session = await self._get_session()
        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": request_id,
        }

        last_error = None
        for attempt in range(self.retries):
            try:
                async with session.post(self.rpc_url, json=payload) as response:
                    data = await response.json()

                    if "error" in data:
                        error = data["error"]
                        raise RPCError(
                            error.get("code", -1),
                            error.get("message", "Unknown error"),
                            error.get("data"),
                        )

                    return data.get("result")

            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                last_error = e
                if attempt < self.retries - 1:
                    await asyncio.sleep(2**attempt)  # Exponential backoff
                    continue
                raise

        if last_error:
            raise last_error

        raise RPCError(-1, "Request failed after retries")

    async def get_storage_at(
        self, address: Address, slot: StorageSlot, block: int | None = None
    ) -> StorageSlotResult:
        """Get storage slot value.

        Args:
            address: Contract address
            slot: Storage slot (hex string with 0x prefix)
            block: Block number (None = latest)

        Returns:
            StorageSlotResult with slot value and metadata
        """
        block_param = hex(block) if block is not None else "latest"
        params = [address, slot, block_param]

        value = await self._request("eth_getStorageAt", params)
        block_number = await self.get_block_number()

        query = StorageSlotQuery(proxy_address=address, slot=slot, block=block)

        # Decode address if slot contains address (last 20 bytes of 32-byte value)
        decoded_address = None
        if value and value != "0x" + "0" * 64:
            # Extract last 20 bytes (address is right-aligned in bytes32)
            address_hex = value[-40:]  # Last 40 hex chars = 20 bytes
            decoded_address = Address("0x" + address_hex)

        return StorageSlotResult(
            query=query,
            value=Bytes32(value),
            decoded_address=decoded_address,
            block_number=block_number,
        )

    async def get_code(self, address: Address, block: int | None = None) -> str:
        """Get contract bytecode.

        Args:
            address: Contract address
            block: Block number (None = latest)

        Returns:
            Bytecode as hex string (0x-prefixed)
        """
        block_param = hex(block) if block is not None else "latest"
        params = [address, block_param]

        bytecode = await self._request("eth_getCode", params)
        return bytecode if bytecode else "0x"

    async def get_block_number(self) -> int:
        """Get latest block number.

        Returns:
            Latest block number
        """
        result = await self._request("eth_blockNumber", [])
        return int(result, 16)

    async def close(self) -> None:
        """Close RPC client session."""
        if self._session and not self._session.closed:
            await self._session.close()

    async def __aenter__(self):
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.close()
