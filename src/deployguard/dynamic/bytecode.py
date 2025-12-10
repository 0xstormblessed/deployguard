"""Bytecode analyzer for contract bytecode analysis."""

from eth_utils import keccak

from deployguard.constants import (
    OPCODE_CREATE,
    OPCODE_CREATE2,
    OPCODE_DELEGATECALL,
    OPCODE_SELFDESTRUCT,
)
from deployguard.models.core import Address, Bytecode
from deployguard.models.dynamic import BytecodeAnalysis


class BytecodeAnalyzer:
    """Analyzes contract bytecode for security patterns.

    This analyzer scans bytecode for:
    - Dangerous opcodes (DELEGATECALL, SELFDESTRUCT)
    - Proxy patterns (EIP-1167 minimal proxy)
    - Risk indicators
    """

    # EIP-1167 minimal proxy pattern (first 45 bytes)
    # 0x363d3d373d3d3d363d73<address>5af43d82803e903d91602b57fd5bf3
    EIP1167_PREFIX = bytes.fromhex("363d3d373d3d3d363d73")
    EIP1167_SUFFIX = bytes.fromhex("5af43d82803e903d91602b57fd5bf3")

    def analyze(self, address: Address, bytecode: Bytecode) -> BytecodeAnalysis:
        """Analyze contract bytecode.

        Args:
            address: Contract address
            bytecode: Contract bytecode (hex string with 0x prefix)

        Returns:
            BytecodeAnalysis with detected patterns and risks
        """
        # Remove 0x prefix and convert to bytes
        bytecode_hex = bytecode[2:] if bytecode.startswith("0x") else bytecode
        bytecode_bytes = bytes.fromhex(bytecode_hex)

        # Calculate bytecode hash (keccak256)
        bytecode_hash = self._calculate_hash(bytecode_bytes)

        # Scan for opcodes
        has_delegatecall = OPCODE_DELEGATECALL in bytecode_bytes
        has_selfdestruct = OPCODE_SELFDESTRUCT in bytecode_bytes
        has_create = OPCODE_CREATE in bytecode_bytes
        has_create2 = OPCODE_CREATE2 in bytecode_bytes

        # Detect proxy patterns
        is_minimal_proxy = self._is_eip1167_proxy(bytecode_bytes)
        is_proxy_pattern = has_delegatecall and not has_selfdestruct and not is_minimal_proxy

        # Generate risk indicators
        risk_indicators = []
        if has_delegatecall:
            risk_indicators.append("Contains DELEGATECALL opcode")
        if has_selfdestruct:
            risk_indicators.append("Contains SELFDESTRUCT opcode")
        if has_create or has_create2:
            risk_indicators.append("Contains CREATE/CREATE2 opcodes")
        if is_proxy_pattern:
            risk_indicators.append("Matches proxy pattern (DELEGATECALL without SELFDESTRUCT)")

        return BytecodeAnalysis(
            address=address,
            bytecode=bytecode,
            bytecode_hash=bytecode_hash,
            has_delegatecall=has_delegatecall,
            has_selfdestruct=has_selfdestruct,
            has_create=has_create,
            has_create2=has_create2,
            is_proxy_pattern=is_proxy_pattern,
            is_minimal_proxy=is_minimal_proxy,
            risk_indicators=risk_indicators,
        )

    def _calculate_hash(self, bytecode_bytes: bytes) -> str:
        """Calculate keccak256 hash of bytecode.

        Args:
            bytecode_bytes: Bytecode as bytes

        Returns:
            Hash as hex string (0x-prefixed)
        """
        hash_bytes = keccak(bytecode_bytes)
        return "0x" + hash_bytes.hex()

    def _is_eip1167_proxy(self, bytecode_bytes: bytes) -> bool:
        """Check if bytecode matches EIP-1167 minimal proxy pattern.

        Args:
            bytecode_bytes: Bytecode as bytes

        Returns:
            True if matches EIP-1167 pattern
        """
        if len(bytecode_bytes) < 45:
            return False

        # Check prefix (first 10 bytes)
        if bytecode_bytes[:10] != self.EIP1167_PREFIX:
            return False

        # Check suffix (last 15 bytes)
        if len(bytecode_bytes) < 45:
            return False
        if bytecode_bytes[-15:] != self.EIP1167_SUFFIX:
            return False

        return True
