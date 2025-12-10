"""Dynamic analysis module for DeployGuard.

This module provides on-chain verification of proxy contracts by querying
EIP-1967 storage slots and analyzing bytecode.
"""

from deployguard.dynamic.analyzer import (
    DynamicAnalyzer,
    get_implementation_address,
    quick_check,
    verify_proxy,
)
from deployguard.dynamic.bytecode import BytecodeAnalyzer
from deployguard.dynamic.rpc_client import RPCClient

__all__ = [
    "RPCClient",
    "BytecodeAnalyzer",
    "DynamicAnalyzer",
    "quick_check",
    "get_implementation_address",
    "verify_proxy",
]
