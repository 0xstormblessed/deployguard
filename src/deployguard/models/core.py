"""Core types and validation functions."""

import re
from dataclasses import dataclass
from typing import NewType

from eth_utils import to_checksum_address

# Type aliases for Ethereum types
Address = NewType("Address", str)
StorageSlot = NewType("StorageSlot", str)
Bytes32 = NewType("Bytes32", str)
Bytecode = NewType("Bytecode", str)


def is_valid_address(addr: str) -> bool:
    """Validate Ethereum address format.

    Args:
        addr: Address string to validate

    Returns:
        True if address is valid format (0x + 40 hex chars)
    """
    return bool(re.match(r"^0x[a-fA-F0-9]{40}$", addr))


def is_valid_bytes32(value: str) -> bool:
    """Validate bytes32 format.

    Args:
        value: Bytes32 string to validate

    Returns:
        True if value is valid format (0x + 64 hex chars)
    """
    return bool(re.match(r"^0x[a-fA-F0-9]{64}$", value))


def normalize_address(addr: str) -> Address:
    """Normalize address to checksummed format.

    Args:
        addr: Address string to normalize

    Returns:
        Checksummed address

    Raises:
        ValueError: If address format is invalid
    """
    if not is_valid_address(addr):
        raise ValueError(f"Invalid address format: {addr}")
    return Address(to_checksum_address(addr))


@dataclass
class SourceLocation:
    """Tracks position in source code for findings.

    Attributes:
        file_path: Path to source file
        line_number: 1-indexed line number
        column: 0-indexed column (optional, -1 if not specified)
        line_content: The actual line content for display
    """

    file_path: str
    line_number: int
    column: int = -1
    line_content: str = ""

    def __post_init__(self) -> None:
        """Validate source location."""
        if self.line_number < 1:
            raise ValueError(f"Line number must be >= 1, got {self.line_number}")


@dataclass
class SourceFragment:
    """A piece of source code with context.

    Attributes:
        code: The flagged code snippet
        location: Source location of the code
        context_before: 2-3 lines before for context
        context_after: 2-3 lines after for context
    """

    code: str
    location: SourceLocation
    context_before: list[str]
    context_after: list[str]

    def __post_init__(self) -> None:
        """Validate source fragment."""
        if not self.code:
            raise ValueError("Code snippet cannot be empty")

