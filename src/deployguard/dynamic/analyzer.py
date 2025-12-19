"""Dynamic analyzer for on-chain proxy verification."""

import uuid

from deployguard.constants import (
    EIP1967_ADMIN_SLOT,
    EIP1967_BEACON_SLOT,
    EIP1967_IMPLEMENTATION_SLOT,
)
from deployguard.dynamic.bytecode import BytecodeAnalyzer
from deployguard.dynamic.rpc_client import RPCClient
from deployguard.models.core import Address, StorageSlot
from deployguard.models.dynamic import (
    BytecodeAnalysis,
    ProxyStandard,
    ProxyState,
    ProxyVerification,
    StorageSlotResult,
)
from deployguard.config import DeployGuardConfig
from deployguard.models.report import AnalysisReport, AnalysisType, Finding, ReportSummary
from deployguard.models.rules import RuleViolation
from deployguard.rules.executors import DynamicRuleExecutor


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

    async def verify_proxy(self, verification: ProxyVerification) -> ProxyState:
        """Verify proxy contract state.

        Args:
            verification: Verification parameters

        Returns:
            ProxyState with on-chain state
        """
        # Query implementation slot
        impl_slot = StorageSlot(EIP1967_IMPLEMENTATION_SLOT)
        impl_result = await self.rpc_client.get_storage_at(verification.proxy_address, impl_slot)

        # Query admin slot if requested
        admin_result: StorageSlotResult | None = None
        if verification.expected_admin is not None:
            admin_slot = StorageSlot(EIP1967_ADMIN_SLOT)
            admin_result = await self.rpc_client.get_storage_at(
                verification.proxy_address, admin_slot
            )

        # Query beacon slot if requested
        beacon_result: StorageSlotResult | None = None
        if verification.check_beacon:
            beacon_slot = StorageSlot(EIP1967_BEACON_SLOT)
            beacon_result = await self.rpc_client.get_storage_at(
                verification.proxy_address, beacon_slot
            )

        # Get proxy bytecode
        proxy_bytecode = await self.rpc_client.get_code(verification.proxy_address)

        # Get implementation bytecode if available
        impl_bytecode: str | None = None
        impl_bytecode_analysis: BytecodeAnalysis | None = None
        if impl_result.decoded_address:
            impl_bytecode = await self.rpc_client.get_code(impl_result.decoded_address)
            # Analyze implementation bytecode for shadow contract detection
            if impl_bytecode:
                impl_bytecode_analysis = await self.analyze_bytecode(
                    impl_result.decoded_address,
                    impl_bytecode,
                )

        # Detect proxy standard
        proxy_standard = self._detect_proxy_standard(impl_result, admin_result, beacon_result)

        # Check if initialized
        is_initialized = self._is_initialized(impl_result)

        return ProxyState(
            proxy_address=verification.proxy_address,
            implementation_slot=impl_result,
            admin_slot=admin_result,
            beacon_slot=beacon_result,
            proxy_bytecode=proxy_bytecode,
            implementation_bytecode=impl_bytecode,
            implementation_bytecode_analysis=impl_bytecode_analysis,
            proxy_standard=proxy_standard,
            is_initialized=is_initialized,
        )

    async def analyze_bytecode(self, address: Address, bytecode: str) -> BytecodeAnalysis:
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
        admin_result: StorageSlotResult | None,
        beacon_result: StorageSlotResult | None,
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


async def quick_check(
    proxy_address: Address,
    expected_implementation: Address,
    rpc_url: str,
) -> bool:
    """Quick pass/fail check for proxy implementation.

    Args:
        proxy_address: Address of proxy contract
        expected_implementation: Expected implementation address
        rpc_url: RPC endpoint URL

    Returns:
        True if implementation matches, False otherwise
    """
    async with RPCClient(rpc_url) as rpc_client:
        analyzer = DynamicAnalyzer(rpc_client)
        verification = ProxyVerification(
            proxy_address=proxy_address,
            expected_implementation=expected_implementation,
            rpc_url=rpc_url,
        )
        proxy_state = await analyzer.verify_proxy(verification)
        actual_impl = proxy_state.implementation_slot.decoded_address

        if not actual_impl:
            return False

        return actual_impl.lower() == expected_implementation.lower()


async def get_implementation_address(proxy_address: Address, rpc_url: str) -> Address | None:
    """Get the current implementation address of a proxy.

    Args:
        proxy_address: Address of proxy contract
        rpc_url: RPC endpoint URL

    Returns:
        Implementation address if found, None if slot is empty or proxy standard unknown
    """
    async with RPCClient(rpc_url) as rpc_client:
        impl_slot = StorageSlot(EIP1967_IMPLEMENTATION_SLOT)
        impl_result = await rpc_client.get_storage_at(proxy_address, impl_slot)
        return impl_result.decoded_address


def _violation_to_finding(violation: RuleViolation, finding_id: str) -> Finding:
    """Convert RuleViolation to Finding.

    Args:
        violation: Rule violation to convert
        finding_id: Unique finding ID

    Returns:
        Finding object
    """
    # Build on-chain evidence from storage/bytecode data
    on_chain_evidence: dict | None = None
    if violation.storage_data or violation.bytecode_data:
        on_chain_evidence = {}
        if violation.storage_data:
            on_chain_evidence["storage_slot"] = {
                "slot": str(violation.storage_data.query.slot),
                "value": str(violation.storage_data.value),
                "decoded_address": (
                    str(violation.storage_data.decoded_address)
                    if violation.storage_data.decoded_address
                    else None
                ),
                "block_number": violation.storage_data.block_number,
            }
        if violation.bytecode_data:
            on_chain_evidence["bytecode"] = {
                "address": str(violation.bytecode_data.address),
                "has_delegatecall": violation.bytecode_data.has_delegatecall,
                "has_selfdestruct": violation.bytecode_data.has_selfdestruct,
                "is_proxy_pattern": violation.bytecode_data.is_proxy_pattern,
                "risk_indicators": violation.bytecode_data.risk_indicators,
            }
        if violation.context:
            on_chain_evidence["context"] = violation.context

    return Finding(
        id=finding_id,
        rule_id=violation.rule.rule_id,
        title=violation.rule.name,
        description=violation.message,
        severity=violation.severity,
        recommendation=violation.recommendation,
        on_chain_evidence=on_chain_evidence,
        references=violation.rule.references,
        hack_references=violation.rule.hack_references,
        real_world_context=violation.rule.real_world_context,
    )


async def verify_proxy(
    proxy_address: Address,
    expected_implementation: Address,
    rpc_url: str,
    expected_admin: Address | None = None,
    config: DeployGuardConfig | None = None,
) -> AnalysisReport:
    """Verify a proxy contract's on-chain state and run all dynamic rules.

    Args:
        proxy_address: Address of the proxy contract
        expected_implementation: Expected implementation address
        rpc_url: RPC endpoint URL
        expected_admin: Optional expected admin address
        config: Optional configuration for rule filtering

    Returns:
        AnalysisReport with findings from all dynamic rules

    Raises:
        RPCError: If RPC calls fail
    """
    async with RPCClient(rpc_url) as rpc_client:
        analyzer = DynamicAnalyzer(rpc_client)
        verification = ProxyVerification(
            proxy_address=proxy_address,
            expected_implementation=expected_implementation,
            rpc_url=rpc_url,
            expected_admin=expected_admin,
        )

        # Get proxy state (includes implementation_bytecode_analysis)
        proxy_state = await analyzer.verify_proxy(verification)

        # Run all dynamic rules via executor
        executor = DynamicRuleExecutor(config)
        violations = await executor.execute(
            proxy_state,
            str(expected_implementation),
            str(expected_admin) if expected_admin else None,
        )

        # Convert violations to findings
        findings = [
            _violation_to_finding(violation, f"finding-{i}")
            for i, violation in enumerate(violations, start=1)
        ]

        # Build summary
        # Count rules executed (get from registry)
        from deployguard.rules.registry import registry
        rules_executed = len(registry.get_dynamic_rules())

        summary = ReportSummary(
            total_findings=len(findings),
            critical_count=sum(1 for f in findings if f.severity.value == "critical"),
            high_count=sum(1 for f in findings if f.severity.value == "high"),
            medium_count=sum(1 for f in findings if f.severity.value == "medium"),
            low_count=sum(1 for f in findings if f.severity.value == "low"),
            info_count=sum(1 for f in findings if f.severity.value == "info"),
            contracts_verified=1,
            rules_executed=rules_executed,
        )

        # Determine exit code (non-zero if Critical or High findings)
        exit_code = 0 if summary.passed else 1

        # Redact RPC URL for security (keep only scheme and domain)
        redacted_rpc_url: str | None = None
        if rpc_url:
            try:
                from urllib.parse import urlparse

                parsed = urlparse(rpc_url)
                redacted_rpc_url = f"{parsed.scheme}://{parsed.netloc.split('@')[-1].split(':')[0]}"
            except Exception:
                redacted_rpc_url = "redacted"

        return AnalysisReport(
            report_id=str(uuid.uuid4()),
            analysis_type=AnalysisType.DYNAMIC,
            target_addresses=[proxy_address],
            rpc_url=redacted_rpc_url,
            findings=findings,
            summary=summary,
            exit_code=exit_code,
            actual_implementation=proxy_state.implementation_slot.decoded_address,
            actual_admin=(
                proxy_state.admin_slot.decoded_address
                if proxy_state.admin_slot
                else None
            ),
        )
