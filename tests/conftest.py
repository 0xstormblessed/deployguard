"""Pytest configuration and fixtures."""

import pytest


@pytest.fixture
def sample_address() -> str:
    """Sample Ethereum address for testing."""
    return "0x1234567890123456789012345678901234567890"


@pytest.fixture
def sample_bytes32() -> str:
    """Sample bytes32 value for testing."""
    return "0x" + "0" * 64

