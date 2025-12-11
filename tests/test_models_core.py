"""Tests for core models."""

import pytest

from deployguard.models.core import (
    Address,
    Bytes32,
    SourceFragment,
    SourceLocation,
    is_valid_address,
    is_valid_bytes32,
    normalize_address,
)


class TestAddressValidation:
    """Tests for address validation."""

    def test_valid_address(self) -> None:
        """Test valid address format."""
        assert is_valid_address("0x1234567890123456789012345678901234567890") is True

    def test_invalid_address_short(self) -> None:
        """Test invalid address (too short)."""
        assert is_valid_address("0x123") is False

    def test_invalid_address_no_prefix(self) -> None:
        """Test invalid address (no 0x prefix)."""
        assert is_valid_address("1234567890123456789012345678901234567890") is False

    def test_invalid_address_invalid_chars(self) -> None:
        """Test invalid address (invalid characters)."""
        assert is_valid_address("0x123456789012345678901234567890123456789g") is False

    def test_normalize_address(self) -> None:
        """Test address normalization."""
        addr = normalize_address("0x1234567890123456789012345678901234567890")
        # Address is a NewType(str), so check it's a string at runtime
        assert isinstance(addr, str)
        assert addr.startswith("0x")
        assert len(addr) == 42  # 0x + 40 hex chars

    def test_normalize_invalid_address(self) -> None:
        """Test normalization of invalid address raises error."""
        with pytest.raises(ValueError):
            normalize_address("invalid")


class TestBytes32Validation:
    """Tests for bytes32 validation."""

    def test_valid_bytes32(self) -> None:
        """Test valid bytes32 format."""
        assert is_valid_bytes32("0x" + "0" * 64) is True

    def test_invalid_bytes32_short(self) -> None:
        """Test invalid bytes32 (too short)."""
        assert is_valid_bytes32("0x123") is False

    def test_invalid_bytes32_no_prefix(self) -> None:
        """Test invalid bytes32 (no 0x prefix)."""
        assert is_valid_bytes32("0" * 64) is False


class TestSourceLocation:
    """Tests for SourceLocation model."""

    def test_create_source_location(self) -> None:
        """Test creating a source location."""
        loc = SourceLocation(
            file_path="script/Deploy.s.sol",
            line_number=10,
            column=5,
            line_content="    ERC1967Proxy proxy = new ERC1967Proxy(impl, \"\");",
        )
        assert loc.file_path == "script/Deploy.s.sol"
        assert loc.line_number == 10
        assert loc.column == 5

    def test_source_location_invalid_line(self) -> None:
        """Test source location with invalid line number."""
        with pytest.raises(ValueError):
            SourceLocation(file_path="test.sol", line_number=0)

    def test_source_location_defaults(self) -> None:
        """Test source location with defaults."""
        loc = SourceLocation(file_path="test.sol", line_number=1)
        assert loc.column == -1
        assert loc.line_content == ""


class TestSourceFragment:
    """Tests for SourceFragment model."""

    def test_create_source_fragment(self) -> None:
        """Test creating a source fragment."""
        loc = SourceLocation(file_path="test.sol", line_number=10, line_content="code")
        fragment = SourceFragment(
            code="code",
            location=loc,
            context_before=["line 8", "line 9"],
            context_after=["line 11", "line 12"],
        )
        assert fragment.code == "code"
        assert fragment.location == loc
        assert len(fragment.context_before) == 2
        assert len(fragment.context_after) == 2

    def test_source_fragment_empty_code(self) -> None:
        """Test source fragment with empty code raises error."""
        loc = SourceLocation(file_path="test.sol", line_number=1)
        with pytest.raises(ValueError):
            SourceFragment(code="", location=loc, context_before=[], context_after=[])

