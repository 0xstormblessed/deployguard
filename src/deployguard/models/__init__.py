"""Data models for DeployGuard."""

from deployguard.models.core import (
    Address,
    Bytes32,
    Bytecode,
    SourceFragment,
    SourceLocation,
    StorageSlot,
    is_valid_address,
    is_valid_bytes32,
    normalize_address,
)
from deployguard.models.dynamic import (
    BytecodeAnalysis,
    ProxyStandard,
    ProxyState,
    ProxyVerification,
    StorageSlotQuery,
    StorageSlotResult,
)
from deployguard.models.report import (
    AnalysisReport,
    AnalysisType,
    Finding,
    ReportSummary,
)
from deployguard.models.rules import (
    Rule,
    RuleCategory,
    RuleViolation,
    Severity,
)
from deployguard.models.static import (
    BoundaryType,
    ProxyDeployment,
    ProxyType,
    ScriptAnalysis,
    ScriptType,
    TransactionBoundary,
    VariableInfo,
)
from deployguard.models.testing import (
    CoverageAnalysis,
    FoundryProject,
    ScriptTestCoverage,
)

__all__ = [
    # Core types
    "Address",
    "StorageSlot",
    "Bytes32",
    "Bytecode",
    "SourceLocation",
    "SourceFragment",
    "is_valid_address",
    "is_valid_bytes32",
    "normalize_address",
    # Static analysis models
    "ProxyType",
    "ProxyDeployment",
    "BoundaryType",
    "TransactionBoundary",
    "ScriptType",
    "ScriptAnalysis",
    "VariableInfo",
    # Dynamic analysis models
    "StorageSlotQuery",
    "StorageSlotResult",
    "ProxyVerification",
    "ProxyStandard",
    "ProxyState",
    "BytecodeAnalysis",
    # Rule system models
    "Severity",
    "RuleCategory",
    "Rule",
    "RuleViolation",
    # Report models
    "Finding",
    "AnalysisType",
    "AnalysisReport",
    "ReportSummary",
    # Testing models
    "FoundryProject",
    "ScriptTestCoverage",
    "CoverageAnalysis",
]

