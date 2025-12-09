"""Models for analysis reports."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional

from deployguard.models.core import Address, SourceLocation
from deployguard.models.rules import Severity


class AnalysisType(Enum):
    """Types of analysis."""

    STATIC = "static"
    DYNAMIC = "dynamic"
    BOTH = "both"


@dataclass
class Finding:
    """A single finding in the report.

    Attributes:
        id: Unique finding ID
        rule_id: Rule that triggered this finding
        title: Short title
        description: Detailed description
        severity: Severity level
        location: Source location (if applicable)
        on_chain_evidence: On-chain evidence (if applicable)
        recommendation: How to fix the issue
        timestamp: When finding was created
        tool_version: Version of tool that created finding
    """

    id: str
    rule_id: str
    title: str
    description: str
    severity: Severity
    location: Optional[SourceLocation] = None
    on_chain_evidence: Optional[dict] = None
    recommendation: str = ""
    timestamp: datetime = field(default_factory=datetime.now)
    tool_version: str = "0.1.0"


@dataclass
class ReportSummary:
    """Summary statistics for a report.

    Attributes:
        total_findings: Total number of findings
        critical_count: Number of critical findings
        high_count: Number of high findings
        medium_count: Number of medium findings
        low_count: Number of low findings
        info_count: Number of info findings
        passed: True if no Critical/High findings
        files_analyzed: Number of files analyzed
        contracts_verified: Number of contracts verified
        rules_executed: Number of rules executed
    """

    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    passed: bool = True
    files_analyzed: int = 0
    contracts_verified: int = 0
    rules_executed: int = 0

    def __post_init__(self) -> None:
        """Calculate passed status."""
        self.passed = self.critical_count == 0 and self.high_count == 0


@dataclass
class AnalysisReport:
    """Complete analysis report.

    Attributes:
        report_id: Unique report ID
        timestamp: When report was created
        tool_version: Version of tool
        analysis_type: Type of analysis performed
        input_files: Files analyzed (for static)
        target_addresses: Addresses verified (for dynamic)
        rpc_url: RPC URL used (redacted, for dynamic)
        findings: List of findings
        summary: Report summary statistics
        exit_code: Recommended exit code
    """

    report_id: str
    timestamp: datetime = field(default_factory=datetime.now)
    tool_version: str = "0.1.0"
    analysis_type: AnalysisType = AnalysisType.STATIC
    input_files: list[str] = field(default_factory=list)
    target_addresses: list[Address] = field(default_factory=list)
    rpc_url: Optional[str] = None
    findings: list[Finding] = field(default_factory=list)
    summary: ReportSummary = field(default_factory=ReportSummary)
    exit_code: int = 0

