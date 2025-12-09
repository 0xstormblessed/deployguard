"""Models for static analysis of deployment scripts."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from deployguard.models.core import SourceLocation


class ProxyType(Enum):
    """Types of proxy contracts."""

    ERC1967_PROXY = "ERC1967Proxy"
    TRANSPARENT_UPGRADEABLE_PROXY = "TransparentUpgradeableProxy"
    UUPS_UPGRADEABLE = "UUPSUpgradeable"
    BEACON_PROXY = "BeaconProxy"
    MINIMAL_PROXY = "MinimalProxy"  # EIP-1167 clones
    CUSTOM = "Custom"  # User-defined proxy pattern


class ScriptType(Enum):
    """Types of deployment scripts."""

    FOUNDRY = "foundry"  # .s.sol deployment script


class BoundaryType(Enum):
    """Types of transaction boundaries in deployment scripts."""

    VM_BROADCAST = "vm.broadcast"
    VM_START_BROADCAST = "vm.startBroadcast"
    VM_STOP_BROADCAST = "vm.stopBroadcast"


@dataclass
class VariableInfo:
    """Tracks variable assignments for data flow analysis.

    Attributes:
        name: Variable name
        assigned_value: Value if statically determinable
        assignment_location: Where variable is assigned
        is_hardcoded: True if literal address
        is_validated: True if has validation logic
    """

    name: str
    assigned_value: Optional[str] = None
    assignment_location: SourceLocation = field(default_factory=lambda: SourceLocation("", 1))
    is_hardcoded: bool = False
    is_validated: bool = False


@dataclass
class TransactionBoundary:
    """Identifies transaction boundaries in deployment scripts.

    Attributes:
        boundary_type: Type of boundary
        location: Where boundary occurs
        scope_start: Line where scope starts
        scope_end: Line where scope ends (if known)
    """

    boundary_type: BoundaryType
    location: SourceLocation
    scope_start: int
    scope_end: Optional[int] = None


@dataclass
class ProxyDeployment:
    """Represents a detected proxy deployment in a script.

    Attributes:
        proxy_type: Type of proxy contract
        implementation_arg: Implementation address/variable
        init_data_arg: Initialization data argument
        location: Where deployment occurs
        has_empty_init: True if init data is empty/0x
        is_atomic: True if deploy+init in same tx
        tx_boundary_before: vm.broadcast location before deployment
        tx_boundary_after: Next vm.broadcast location after deployment
    """

    proxy_type: ProxyType
    implementation_arg: str
    init_data_arg: str
    location: SourceLocation
    has_empty_init: bool = False
    is_atomic: bool = False
    tx_boundary_before: Optional[SourceLocation] = None
    tx_boundary_after: Optional[SourceLocation] = None


@dataclass
class ScriptAnalysis:
    """Complete analysis result for a deployment script.

    Attributes:
        file_path: Path to analyzed script
        script_type: Type of script
        proxy_deployments: List of detected proxy deployments
        tx_boundaries: List of transaction boundaries
        implementation_variables: Variables that may contain implementation addresses
        has_private_key_env: Uses vm.envUint("PRIVATE_KEY")
        has_ownership_transfer: Calls transferOwnership()
        parse_errors: List of parse errors encountered
        parse_warnings: List of parse warnings encountered
    """

    file_path: str
    script_type: ScriptType
    proxy_deployments: list[ProxyDeployment] = field(default_factory=list)
    tx_boundaries: list[TransactionBoundary] = field(default_factory=list)
    implementation_variables: dict[str, VariableInfo] = field(default_factory=dict)
    has_private_key_env: bool = False
    has_ownership_transfer: bool = False
    parse_errors: list[str] = field(default_factory=list)
    parse_warnings: list[str] = field(default_factory=list)

