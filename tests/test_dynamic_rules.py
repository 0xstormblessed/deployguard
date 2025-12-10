"""Tests for dynamic analysis rules (DG-101 to DG-105)."""

from deployguard.constants import (
    EIP1967_ADMIN_SLOT,
    EIP1967_IMPLEMENTATION_SLOT,
)
from deployguard.models.core import Address, Bytes32, StorageSlot
from deployguard.models.dynamic import (
    BytecodeAnalysis,
    ProxyStandard,
    ProxyState,
    StorageSlotQuery,
    StorageSlotResult,
)
from deployguard.models.rules import Severity
from deployguard.rules.dynamic import (
    RULE_DG_101,
    RULE_DG_102,
    RULE_DG_103,
    RULE_DG_104,
    RULE_DG_105,
    check_admin_mismatch,
    check_implementation_mismatch,
    check_non_standard_proxy,
    check_shadow_contract,
    check_uninitialized_proxy,
)


class TestDG101ImplementationMismatch:
    """Tests for DG-101: Implementation Slot Mismatch."""

    def test_no_violation_when_match(self) -> None:
        """Test no violation when implementation matches."""
        impl_address = Address("0xa1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2")
        proxy_state = ProxyState(
            proxy_address=Address("0x1234567890123456789012345678901234567890"),
            implementation_slot=StorageSlotResult(
                query=StorageSlotQuery(
                    proxy_address=Address("0x1234567890123456789012345678901234567890"),
                    slot=StorageSlot(EIP1967_IMPLEMENTATION_SLOT),
                ),
                value=Bytes32("0x000000000000000000000000a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"),
                decoded_address=impl_address,
                block_number=1000,
            ),
        )

        result = check_implementation_mismatch(proxy_state, impl_address)

        assert result is None

    def test_violation_when_mismatch(self) -> None:
        """Test violation when implementation doesn't match."""
        expected_impl = Address("0xa1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2")
        actual_impl = Address("0xdifferent0000000000000000000000000000000")

        proxy_state = ProxyState(
            proxy_address=Address("0x1234567890123456789012345678901234567890"),
            implementation_slot=StorageSlotResult(
                query=StorageSlotQuery(
                    proxy_address=Address("0x1234567890123456789012345678901234567890"),
                    slot=StorageSlot(EIP1967_IMPLEMENTATION_SLOT),
                ),
                value=Bytes32("0x000000000000000000000000different0000000000000000000000000000000"),
                decoded_address=actual_impl,
                block_number=1000,
            ),
        )

        result = check_implementation_mismatch(proxy_state, expected_impl)

        assert result is not None
        assert result.rule.rule_id == "DG-101"
        assert result.severity == Severity.CRITICAL
        assert expected_impl in result.message
        assert actual_impl in result.message
        assert result.storage_data == proxy_state.implementation_slot
        assert result.context["expected"] == str(expected_impl)
        assert result.context["actual"] == str(actual_impl)

    def test_case_insensitive_match(self) -> None:
        """Test case-insensitive address matching."""
        impl_address_lower = Address("0xa1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2")
        impl_address_upper = Address("0xA1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2")

        proxy_state = ProxyState(
            proxy_address=Address("0x1234567890123456789012345678901234567890"),
            implementation_slot=StorageSlotResult(
                query=StorageSlotQuery(
                    proxy_address=Address("0x1234567890123456789012345678901234567890"),
                    slot=StorageSlot(EIP1967_IMPLEMENTATION_SLOT),
                ),
                value=Bytes32("0x000000000000000000000000A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2"),
                decoded_address=impl_address_upper,
                block_number=1000,
            ),
        )

        result = check_implementation_mismatch(proxy_state, impl_address_lower)

        assert result is None

    def test_rule_metadata(self) -> None:
        """Test rule metadata is correct."""
        assert RULE_DG_101.rule_id == "DG-101"
        assert RULE_DG_101.severity == Severity.CRITICAL
        assert len(RULE_DG_101.references) > 0
        assert RULE_DG_101.remediation is not None


class TestDG102ShadowContract:
    """Tests for DG-102: Shadow Contract Detection."""

    def test_no_violation_without_delegatecall(self) -> None:
        """Test no violation when implementation has no DELEGATECALL."""
        proxy_state = ProxyState(
            proxy_address=Address("0x1234567890123456789012345678901234567890"),
            implementation_slot=StorageSlotResult(
                query=StorageSlotQuery(
                    proxy_address=Address("0x1234567890123456789012345678901234567890"),
                    slot=StorageSlot(EIP1967_IMPLEMENTATION_SLOT),
                ),
                value=Bytes32("0x000000000000000000000000a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"),
                decoded_address=Address("0xa1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"),
                block_number=1000,
            ),
        )

        bytecode_analysis = BytecodeAnalysis(
            address=Address("0xa1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"),
            bytecode="0x6080604052348015600f57600080fd5b50",
            bytecode_hash="0xabcd",
            has_delegatecall=False,
            has_selfdestruct=False,
            is_proxy_pattern=False,
        )

        result = check_shadow_contract(proxy_state, bytecode_analysis)

        assert result is None

    def test_violation_with_delegatecall(self) -> None:
        """Test violation when implementation contains DELEGATECALL."""
        proxy_state = ProxyState(
            proxy_address=Address("0x1234567890123456789012345678901234567890"),
            implementation_slot=StorageSlotResult(
                query=StorageSlotQuery(
                    proxy_address=Address("0x1234567890123456789012345678901234567890"),
                    slot=StorageSlot(EIP1967_IMPLEMENTATION_SLOT),
                ),
                value=Bytes32("0x000000000000000000000000a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"),
                decoded_address=Address("0xa1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"),
                block_number=1000,
            ),
        )

        bytecode_analysis = BytecodeAnalysis(
            address=Address("0xa1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"),
            bytecode="0x6080604052F4",  # Contains DELEGATECALL (0xF4)
            bytecode_hash="0xabcd",
            has_delegatecall=True,
            has_selfdestruct=False,
            is_proxy_pattern=True,
            risk_indicators=["Contains DELEGATECALL opcode"],
        )

        result = check_shadow_contract(proxy_state, bytecode_analysis)

        assert result is not None
        assert result.rule.rule_id == "DG-102"
        assert result.severity == Severity.HIGH
        assert "shadow" in result.message.lower()
        assert result.bytecode_data == bytecode_analysis
        assert result.storage_data == proxy_state.implementation_slot
        assert result.context["has_selfdestruct"] is False
        assert result.context["is_proxy_pattern"] is True

    def test_rule_metadata(self) -> None:
        """Test rule metadata is correct."""
        assert RULE_DG_102.rule_id == "DG-102"
        assert RULE_DG_102.severity == Severity.HIGH
        assert len(RULE_DG_102.references) > 0


class TestDG103UninitializedProxy:
    """Tests for DG-103: Uninitialized Proxy."""

    def test_no_violation_when_initialized(self) -> None:
        """Test no violation when proxy is initialized."""
        proxy_state = ProxyState(
            proxy_address=Address("0x1234567890123456789012345678901234567890"),
            implementation_slot=StorageSlotResult(
                query=StorageSlotQuery(
                    proxy_address=Address("0x1234567890123456789012345678901234567890"),
                    slot=StorageSlot(EIP1967_IMPLEMENTATION_SLOT),
                ),
                value=Bytes32("0x000000000000000000000000a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"),
                decoded_address=Address("0xa1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"),
                block_number=1000,
            ),
        )

        result = check_uninitialized_proxy(proxy_state)

        assert result is None

    def test_violation_when_uninitialized(self) -> None:
        """Test violation when implementation slot is zero."""
        zero_slot = "0x" + "0" * 64
        proxy_state = ProxyState(
            proxy_address=Address("0x1234567890123456789012345678901234567890"),
            implementation_slot=StorageSlotResult(
                query=StorageSlotQuery(
                    proxy_address=Address("0x1234567890123456789012345678901234567890"),
                    slot=StorageSlot(EIP1967_IMPLEMENTATION_SLOT),
                ),
                value=Bytes32(zero_slot),
                decoded_address=None,
                block_number=1000,
            ),
        )

        result = check_uninitialized_proxy(proxy_state)

        assert result is not None
        assert result.rule.rule_id == "DG-103"
        assert result.severity == Severity.HIGH
        assert "uninitialized" in result.message.lower()
        assert result.storage_data == proxy_state.implementation_slot
        assert result.context["slot_value"] == zero_slot

    def test_rule_metadata(self) -> None:
        """Test rule metadata is correct."""
        assert RULE_DG_103.rule_id == "DG-103"
        assert RULE_DG_103.severity == Severity.HIGH
        assert len(RULE_DG_103.references) > 0


class TestDG104AdminMismatch:
    """Tests for DG-104: Admin Slot Mismatch."""

    def test_no_violation_when_match(self) -> None:
        """Test no violation when admin matches."""
        admin_address = Address("0xb1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2")
        proxy_state = ProxyState(
            proxy_address=Address("0x1234567890123456789012345678901234567890"),
            implementation_slot=StorageSlotResult(
                query=StorageSlotQuery(
                    proxy_address=Address("0x1234567890123456789012345678901234567890"),
                    slot=StorageSlot(EIP1967_IMPLEMENTATION_SLOT),
                ),
                value=Bytes32("0x" + "0" * 64),
                block_number=1000,
            ),
            admin_slot=StorageSlotResult(
                query=StorageSlotQuery(
                    proxy_address=Address("0x1234567890123456789012345678901234567890"),
                    slot=StorageSlot(EIP1967_ADMIN_SLOT),
                ),
                value=Bytes32("0x000000000000000000000000b1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"),
                decoded_address=admin_address,
                block_number=1000,
            ),
        )

        result = check_admin_mismatch(proxy_state, admin_address)

        assert result is None

    def test_violation_when_mismatch(self) -> None:
        """Test violation when admin doesn't match."""
        expected_admin = Address("0xb1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2")
        actual_admin = Address("0xdifferent0000000000000000000000000000000")

        proxy_state = ProxyState(
            proxy_address=Address("0x1234567890123456789012345678901234567890"),
            implementation_slot=StorageSlotResult(
                query=StorageSlotQuery(
                    proxy_address=Address("0x1234567890123456789012345678901234567890"),
                    slot=StorageSlot(EIP1967_IMPLEMENTATION_SLOT),
                ),
                value=Bytes32("0x" + "0" * 64),
                block_number=1000,
            ),
            admin_slot=StorageSlotResult(
                query=StorageSlotQuery(
                    proxy_address=Address("0x1234567890123456789012345678901234567890"),
                    slot=StorageSlot(EIP1967_ADMIN_SLOT),
                ),
                value=Bytes32("0x000000000000000000000000different0000000000000000000000000000000"),
                decoded_address=actual_admin,
                block_number=1000,
            ),
        )

        result = check_admin_mismatch(proxy_state, expected_admin)

        assert result is not None
        assert result.rule.rule_id == "DG-104"
        assert result.severity == Severity.MEDIUM
        assert expected_admin in result.message
        assert actual_admin in result.message
        assert result.storage_data == proxy_state.admin_slot
        assert result.context["expected"] == str(expected_admin)
        assert result.context["actual"] == str(actual_admin)

    def test_no_check_when_no_expected_admin(self) -> None:
        """Test no check when expected_admin is None."""
        proxy_state = ProxyState(
            proxy_address=Address("0x1234567890123456789012345678901234567890"),
            implementation_slot=StorageSlotResult(
                query=StorageSlotQuery(
                    proxy_address=Address("0x1234567890123456789012345678901234567890"),
                    slot=StorageSlot(EIP1967_IMPLEMENTATION_SLOT),
                ),
                value=Bytes32("0x" + "0" * 64),
                block_number=1000,
            ),
        )

        result = check_admin_mismatch(proxy_state, None)

        assert result is None

    def test_no_check_when_no_admin_slot(self) -> None:
        """Test no check when proxy has no admin slot."""
        proxy_state = ProxyState(
            proxy_address=Address("0x1234567890123456789012345678901234567890"),
            implementation_slot=StorageSlotResult(
                query=StorageSlotQuery(
                    proxy_address=Address("0x1234567890123456789012345678901234567890"),
                    slot=StorageSlot(EIP1967_IMPLEMENTATION_SLOT),
                ),
                value=Bytes32("0x" + "0" * 64),
                block_number=1000,
            ),
            admin_slot=None,
        )

        result = check_admin_mismatch(
            proxy_state, Address("0xb1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2")
        )

        assert result is None

    def test_rule_metadata(self) -> None:
        """Test rule metadata is correct."""
        assert RULE_DG_104.rule_id == "DG-104"
        assert RULE_DG_104.severity == Severity.MEDIUM
        assert len(RULE_DG_104.references) > 0


class TestDG105NonStandardProxy:
    """Tests for DG-105: Non-Standard Proxy Pattern."""

    def test_no_violation_when_standard(self) -> None:
        """Test no violation when proxy uses standard EIP-1967."""
        proxy_state = ProxyState(
            proxy_address=Address("0x1234567890123456789012345678901234567890"),
            implementation_slot=StorageSlotResult(
                query=StorageSlotQuery(
                    proxy_address=Address("0x1234567890123456789012345678901234567890"),
                    slot=StorageSlot(EIP1967_IMPLEMENTATION_SLOT),
                ),
                value=Bytes32("0x000000000000000000000000a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"),
                decoded_address=Address("0xa1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"),
                block_number=1000,
            ),
            proxy_standard=ProxyStandard.EIP_1967,
        )

        result = check_non_standard_proxy(proxy_state)

        assert result is None

    def test_violation_when_unknown_standard(self) -> None:
        """Test violation when proxy standard is unknown."""
        proxy_state = ProxyState(
            proxy_address=Address("0x1234567890123456789012345678901234567890"),
            implementation_slot=StorageSlotResult(
                query=StorageSlotQuery(
                    proxy_address=Address("0x1234567890123456789012345678901234567890"),
                    slot=StorageSlot(EIP1967_IMPLEMENTATION_SLOT),
                ),
                value=Bytes32("0x" + "0" * 64),
                decoded_address=None,
                block_number=1000,
            ),
            proxy_standard=ProxyStandard.UNKNOWN,
        )

        result = check_non_standard_proxy(proxy_state)

        assert result is not None
        assert result.rule.rule_id == "DG-105"
        assert result.severity == Severity.INFO
        assert "non-standard" in result.message.lower() or "standard" in result.message.lower()
        assert result.context["proxy_standard"] == "unknown"
        assert result.context["implementation_slot_empty"] is True

    def test_rule_metadata(self) -> None:
        """Test rule metadata is correct."""
        assert RULE_DG_105.rule_id == "DG-105"
        assert RULE_DG_105.severity == Severity.INFO
        assert len(RULE_DG_105.references) > 0
