"""Tests for dynamic analysis rules (IMPL_MISMATCH to NON_STANDARD_PROXY)."""

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
    RULE_IMPL_MISMATCH,
    RULE_DELEGATECALL_IMPL,
    RULE_UNINITIALIZED_PROXY,
    RULE_ADMIN_MISMATCH,
    RULE_NON_STANDARD_PROXY,
    check_admin_mismatch,
    check_implementation_mismatch,
    check_non_standard_proxy,
    check_uninitialized_proxy,
)
from deployguard.rules.dynamic.delegatecall_impl import rule_delegatecall_impl


class TestDG101ImplementationMismatch:
    """Tests for IMPL_MISMATCH: Implementation Slot Mismatch."""

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
        assert result.rule.rule_id == "IMPL_MISMATCH"
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
        assert RULE_IMPL_MISMATCH.rule_id == "IMPL_MISMATCH"
        assert RULE_IMPL_MISMATCH.severity == Severity.CRITICAL
        assert len(RULE_IMPL_MISMATCH.references) > 0
        assert RULE_IMPL_MISMATCH.remediation is not None


class TestDelegatecallImpl:
    """Tests for DELEGATECALL_IMPL: Implementation Contains DELEGATECALL."""

    @staticmethod
    async def _check(proxy_state: ProxyState) -> list:
        """Helper to run async check."""
        return await rule_delegatecall_impl.check(proxy_state, "0x0", None)

    def test_no_violation_without_delegatecall(self) -> None:
        """Test no violation when implementation has no DELEGATECALL."""
        import asyncio

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
            implementation_bytecode_analysis=BytecodeAnalysis(
                address=Address("0xa1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"),
                bytecode="0x6080604052348015600f57600080fd5b50",
                bytecode_hash="0xabcd",
                has_delegatecall=False,
                has_selfdestruct=False,
                is_proxy_pattern=False,
            ),
        )

        results = asyncio.run(self._check(proxy_state))
        assert len(results) == 0

    def test_violation_with_delegatecall(self) -> None:
        """Test violation when implementation contains DELEGATECALL."""
        import asyncio

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
            implementation_bytecode_analysis=BytecodeAnalysis(
                address=Address("0xa1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"),
                bytecode="0x6080604052F4",  # Contains DELEGATECALL (0xF4)
                bytecode_hash="0xabcd",
                has_delegatecall=True,
                has_selfdestruct=False,
                is_proxy_pattern=True,
                risk_indicators=["Contains DELEGATECALL opcode"],
            ),
        )

        results = asyncio.run(self._check(proxy_state))

        assert len(results) == 1
        result = results[0]
        assert result.rule.rule_id == "DELEGATECALL_IMPL"
        assert result.severity == Severity.INFO
        assert "delegatecall" in result.message.lower()
        assert result.context["has_selfdestruct"] is False
        assert result.context["is_proxy_pattern"] is True

    def test_rule_metadata(self) -> None:
        """Test rule metadata is correct."""
        assert RULE_DELEGATECALL_IMPL.rule_id == "DELEGATECALL_IMPL"
        # INFO severity - DELEGATECALL is expected for UUPS proxies
        assert RULE_DELEGATECALL_IMPL.severity == Severity.INFO
        assert len(RULE_DELEGATECALL_IMPL.references) > 0


class TestDG103UninitializedProxy:
    """Tests for UNINITIALIZED_PROXY: Uninitialized Proxy."""

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
        assert result.rule.rule_id == "UNINITIALIZED_PROXY"
        assert result.severity == Severity.HIGH
        assert "uninitialized" in result.message.lower()
        assert result.storage_data == proxy_state.implementation_slot
        assert result.context["slot_value"] == zero_slot

    def test_rule_metadata(self) -> None:
        """Test rule metadata is correct."""
        assert RULE_UNINITIALIZED_PROXY.rule_id == "UNINITIALIZED_PROXY"
        assert RULE_UNINITIALIZED_PROXY.severity == Severity.HIGH
        assert len(RULE_UNINITIALIZED_PROXY.references) > 0


class TestDG104AdminMismatch:
    """Tests for ADMIN_MISMATCH: Admin Slot Mismatch."""

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
        assert result.rule.rule_id == "ADMIN_MISMATCH"
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
        assert RULE_ADMIN_MISMATCH.rule_id == "ADMIN_MISMATCH"
        assert RULE_ADMIN_MISMATCH.severity == Severity.MEDIUM
        assert len(RULE_ADMIN_MISMATCH.references) > 0


class TestDG105NonStandardProxy:
    """Tests for NON_STANDARD_PROXY: Non-Standard Proxy Pattern."""

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
        assert result.rule.rule_id == "NON_STANDARD_PROXY"
        assert result.severity == Severity.INFO
        assert "non-standard" in result.message.lower() or "standard" in result.message.lower()
        assert result.context["proxy_standard"] == "unknown"
        assert result.context["implementation_slot_empty"] is True

    def test_rule_metadata(self) -> None:
        """Test rule metadata is correct."""
        assert RULE_NON_STANDARD_PROXY.rule_id == "NON_STANDARD_PROXY"
        assert RULE_NON_STANDARD_PROXY.severity == Severity.INFO
        assert len(RULE_NON_STANDARD_PROXY.references) > 0
