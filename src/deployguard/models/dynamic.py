"""Models for dynamic analysis of deployed contracts."""

from dataclasses import dataclass
from enum import Enum
from typing import Optional

from deployguard.models.core import Address, Bytecode, Bytes32, StorageSlot


class ProxyStandard(Enum):
    """EIP standards for proxy contracts."""

    EIP_1967 = "EIP-1967"
    EIP_1822 = "EIP-1822"  # UUPS
    EIP_1167 = "EIP-1167"  # Minimal Proxy
    DIAMOND = "EIP-2535"  # Diamond Standard
    UNKNOWN = "unknown"


@dataclass
class StorageSlotQuery:
    """Query parameters for storage slot verification.

    Attributes:
        proxy_address: Address of proxy contract
        slot: Storage slot to query
        block: Block number to query (None = latest)
    """

    proxy_address: Address
    slot: StorageSlot
    block: Optional[int] = None


@dataclass
class StorageSlotResult:
    """Result of a storage slot query.

    Attributes:
        query: Original query parameters
        value: Raw slot value (bytes32)
        decoded_address: Decoded address if slot contains address
        block_number: Block number queried
        timestamp: Block timestamp (if available)
    """

    query: StorageSlotQuery
    value: Bytes32
    decoded_address: Optional[Address] = None
    block_number: int = 0
    timestamp: Optional[int] = None


@dataclass
class ProxyVerification:
    """Input parameters for proxy verification.

    Attributes:
        proxy_address: Address of proxy contract
        expected_implementation: Expected implementation address
        rpc_url: RPC endpoint URL
        expected_admin: Expected admin address (optional)
        check_beacon: Whether to check beacon slot
    """

    proxy_address: Address
    expected_implementation: Address
    rpc_url: str
    expected_admin: Optional[Address] = None
    check_beacon: bool = False


@dataclass
class BytecodeAnalysis:
    """Analysis of contract bytecode.

    Attributes:
        address: Contract address
        bytecode: Contract bytecode
        bytecode_hash: keccak256 hash of bytecode
        has_delegatecall: Whether bytecode contains DELEGATECALL
        has_selfdestruct: Whether bytecode contains SELFDESTRUCT
        has_create: Whether bytecode contains CREATE
        has_create2: Whether bytecode contains CREATE2
        is_proxy_pattern: Whether bytecode looks like a proxy
        is_minimal_proxy: Whether bytecode is EIP-1167 minimal proxy
        risk_indicators: List of risk indicators found
    """

    address: Address
    bytecode: Bytecode
    bytecode_hash: str
    has_delegatecall: bool = False
    has_selfdestruct: bool = False
    has_create: bool = False
    has_create2: bool = False
    is_proxy_pattern: bool = False
    is_minimal_proxy: bool = False
    risk_indicators: list[str] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        """Initialize risk_indicators if None."""
        if self.risk_indicators is None:
            self.risk_indicators = []


@dataclass
class ProxyState:
    """On-chain state of a proxy contract.

    Attributes:
        proxy_address: Address of proxy contract
        implementation_slot: EIP-1967 implementation slot result
        admin_slot: EIP-1967 admin slot result (if available)
        beacon_slot: EIP-1967 beacon slot result (if available)
        proxy_bytecode: Proxy contract bytecode
        implementation_bytecode: Implementation contract bytecode (if available)
        implementation_bytecode_analysis: Analysis of implementation bytecode (if available)
        proxy_standard: Detected proxy standard
        is_initialized: Whether proxy appears initialized
    """

    proxy_address: Address
    implementation_slot: StorageSlotResult
    admin_slot: Optional[StorageSlotResult] = None
    beacon_slot: Optional[StorageSlotResult] = None
    proxy_bytecode: Bytecode = Bytecode("")
    implementation_bytecode: Optional[Bytecode] = None
    implementation_bytecode_analysis: Optional[BytecodeAnalysis] = None
    proxy_standard: ProxyStandard = ProxyStandard.UNKNOWN
    is_initialized: bool = False

