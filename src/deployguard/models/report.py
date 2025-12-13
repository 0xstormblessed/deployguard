"""Models for analysis reports."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path

from deployguard import __version__
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
        references: Links to documentation
        hack_references: Links to exploits and incident reports
        real_world_context: Explanation of why this matters with real examples
        timestamp: When finding was created
        tool_version: Version of tool that created finding
    """

    id: str
    rule_id: str
    title: str
    description: str
    severity: Severity
    location: SourceLocation | None = None
    on_chain_evidence: dict | None = None
    recommendation: str = ""
    references: list[str] = field(default_factory=list)
    hack_references: list[str] = field(default_factory=list)
    real_world_context: str = ""
    timestamp: datetime = field(default_factory=datetime.now)
    tool_version: str = field(default=__version__)


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
    tool_version: str = field(default=__version__)
    analysis_type: AnalysisType = AnalysisType.STATIC
    input_files: list[str] = field(default_factory=list)
    target_addresses: list[Address] = field(default_factory=list)
    rpc_url: str | None = None
    findings: list[Finding] = field(default_factory=list)
    summary: ReportSummary = field(default_factory=ReportSummary)
    exit_code: int = 0


@dataclass
class FileAnalysisResult:
    """Analysis result for a single file in a batch analysis.

    Attributes:
        file_path: Path to the analyzed file
        success: Whether the analysis succeeded
        findings: List of findings for this file
        error: Error message if analysis failed
        error_type: Exception class name if analysis failed
        error_traceback: Full traceback if analysis failed
        analysis_time_ms: Time taken to analyze this file in milliseconds
    """

    file_path: Path
    success: bool
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None
    error_type: str | None = None
    error_traceback: str | None = None
    analysis_time_ms: float = 0.0

    @property
    def has_findings(self) -> bool:
        """Check if this file has any findings."""
        return len(self.findings) > 0

    @property
    def critical_count(self) -> int:
        """Count critical findings."""
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        """Count high severity findings."""
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        """Count medium severity findings."""
        return sum(1 for f in self.findings if f.severity == Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        """Count low severity findings."""
        return sum(1 for f in self.findings if f.severity == Severity.LOW)

    @property
    def info_count(self) -> int:
        """Count info severity findings."""
        return sum(1 for f in self.findings if f.severity == Severity.INFO)


@dataclass
class BatchAnalysisReport:
    """Aggregated report for batch analysis of multiple files.

    Attributes:
        report_id: Unique report ID
        timestamp: When report was created
        tool_version: Version of tool
        project_root: Root directory of the project
        files_analyzed: List of all files that were analyzed
        results: Per-file analysis results
        summary: Aggregated summary statistics
        exit_code: Recommended exit code (non-zero if any Critical/High findings)
        total_analysis_time_ms: Total time taken for all analyses
    """

    report_id: str
    timestamp: datetime = field(default_factory=datetime.now)
    tool_version: str = field(default=__version__)
    project_root: Path = field(default_factory=Path)
    files_analyzed: list[Path] = field(default_factory=list)
    results: list[FileAnalysisResult] = field(default_factory=list)
    summary: ReportSummary = field(default_factory=ReportSummary)
    exit_code: int = 0
    total_analysis_time_ms: float = 0.0

    @property
    def files_with_findings(self) -> list[Path]:
        """Get list of files that have findings."""
        return [r.file_path for r in self.results if r.has_findings]

    @property
    def files_without_findings(self) -> list[Path]:
        """Get list of successfully analyzed files with no findings."""
        return [r.file_path for r in self.results if r.success and not r.has_findings]

    @property
    def failed_files(self) -> list[Path]:
        """Get list of files that failed to analyze."""
        return [r.file_path for r in self.results if not r.success]

    @property
    def status(self) -> str:
        """Get overall status: PASSED or FAILED."""
        return "PASSED" if self.summary.passed else "FAILED"

    def update_summary(self) -> None:
        """Recalculate summary statistics from results."""
        all_findings: list[Finding] = []
        for result in self.results:
            all_findings.extend(result.findings)

        # Check if any files failed to analyze
        failed_count = sum(1 for r in self.results if not r.success)

        self.summary = ReportSummary(
            total_findings=len(all_findings),
            critical_count=sum(1 for f in all_findings if f.severity == Severity.CRITICAL),
            high_count=sum(1 for f in all_findings if f.severity == Severity.HIGH),
            medium_count=sum(1 for f in all_findings if f.severity == Severity.MEDIUM),
            low_count=sum(1 for f in all_findings if f.severity == Severity.LOW),
            info_count=sum(1 for f in all_findings if f.severity == Severity.INFO),
            files_analyzed=len(self.files_analyzed),
            contracts_verified=0,
            rules_executed=0,
        )

        # Override passed status if any files failed to analyze
        if failed_count > 0:
            self.summary.passed = False

        self.exit_code = 1 if not self.summary.passed else 0
