"""Dynamic analyzer for on-chain proxy verification."""

from typing import Optional

from deployguard.constants import (
    EIP1967_ADMIN_SLOT,
    EIP1967_BEACON_SLOT,
    EIP1967_IMPLEMENTATION_SLOT,
)
from deployguard.models.core import Address, StorageSlot
from deployguard.models.dynamic import (
    BytecodeAnalysis,
    ProxyStandard,
    ProxyState,
    ProxyVerification,
    StorageSlotResult,
)
from deployguard.dynamic.bytecode import BytecodeAnalyzer
from deployguard.dynamic.rpc_client import RPCClient


class DynamicAnalyzer:
    """Analyzes deployed proxy contracts on-chain.

    This analyzer:
    - Queries EIP-1967 storage slots
    - Compares actual vs expected implementation addresses
    - Analyzes bytecode for shadow contracts
    - Detects proxy standards
    """

    def __init__(self, rpc_client: RPCClient):
        """Initialize dynamic analyzer.

        Args:
            rpc_client: RPC client for on-chain queries
        """
        self.rpc_client = rpc_client
        self.bytecode_analyzer = BytecodeAnalyzer()

    async def verify_proxy(
        self, verification: ProxyVerification
    ) -> ProxyState:
        """Verify proxy contract state.

        Args:
            verification: Verification parameters

        Returns:
            ProxyState with on-chain state
        """
        # Query implementation slot
        impl_slot = StorageSlot(EIP1967_IMPLEMENTATION_SLOT)
        impl_result = await self.rpc_client.get_storage_at(
            verification.proxy_address, impl_slot
        )

        # Query admin slot if requested
        admin_result: Optional[StorageSlotResult] = None
        if verification.expected_admin is not None:
            admin_slot = StorageSlot(EIP1967_ADMIN_SLOT)
            admin_result = await self.rpc_client.get_storage_at(
                verification.proxy_address, admin_slot
            )

        # Query beacon slot if requested
        beacon_result: Optional[StorageSlotResult] = None
        if verification.check_beacon:
            beacon_slot = StorageSlot(EIP1967_BEACON_SLOT)
            beacon_result = await self.rpc_client.get_storage_at(
                verification.proxy_address, beacon_slot
            )

        # Get proxy bytecode
        proxy_bytecode = await self.rpc_client.get_code(
            verification.proxy_address
        )

        # Get implementation bytecode if available
        impl_bytecode: Optional[str] = None
        if impl_result.decoded_address:
            impl_bytecode = await self.rpc_client.get_code(
                impl_result.decoded_address
            )

        # Detect proxy standard
        proxy_standard = self._detect_proxy_standard(
            impl_result, admin_result, beacon_result
        )

        # Check if initialized
        is_initialized = self._is_initialized(impl_result)

        return ProxyState(
            proxy_address=verification.proxy_address,
            implementation_slot=impl_result,
            admin_slot=admin_result,
            beacon_slot=beacon_result,
            proxy_bytecode=proxy_bytecode,
            implementation_bytecode=impl_bytecode,
            proxy_standard=proxy_standard,
            is_initialized=is_initialized,
        )

    async def analyze_bytecode(
        self, address: Address, bytecode: str
    ) -> BytecodeAnalysis:
        """Analyze contract bytecode.

        Args:
            address: Contract address
            bytecode: Contract bytecode (hex string)

        Returns:
            BytecodeAnalysis with detected patterns
        """
        return self.bytecode_analyzer.analyze(address, bytecode)

    def _detect_proxy_standard(
        self,
        impl_result: StorageSlotResult,
        admin_result: Optional[StorageSlotResult],
        beacon_result: Optional[StorageSlotResult],
    ) -> ProxyStandard:
        """Detect proxy standard from storage slots.

        Args:
            impl_result: Implementation slot result
            admin_result: Admin slot result (if available)
            beacon_result: Beacon slot result (if available)

        Returns:
            Detected proxy standard
        """
        # Check for beacon proxy
        if beacon_result and beacon_result.value != "0x" + "0" * 64:
            return ProxyStandard.EIP_1967  # Beacon proxies use EIP-1967

        # Check for EIP-1967 (has implementation slot)
        if impl_result.value != "0x" + "0" * 64:
            return ProxyStandard.EIP_1967

        # Could be EIP-1822 (UUPS) - would need to check UUPS slot
        # For now, default to EIP-1967 if implementation slot is set
        return ProxyStandard.UNKNOWN

    def _is_initialized(self, impl_result: StorageSlotResult) -> bool:
        """Check if proxy is initialized.

        Args:
            impl_result: Implementation slot result

        Returns:
            True if proxy appears initialized
        """
        zero_slot = "0x" + "0" * 64
        return impl_result.value != zero_slot and impl_result.decoded_address is not None

