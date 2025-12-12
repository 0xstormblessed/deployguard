"""Models for the rule system."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

from deployguard.models.core import SourceFragment, SourceLocation
from deployguard.models.dynamic import BytecodeAnalysis, StorageSlotResult


class Severity(Enum):
    """Severity levels for findings."""

    CRITICAL = "critical"  # Must fix, blocks deployment
    HIGH = "high"  # Should fix, blocks deployment
    MEDIUM = "medium"  # Should fix, warning
    LOW = "low"  # Consider fixing, info
    INFO = "info"  # Informational only


class RuleCategory(Enum):
    """Categories for rules."""

    PROXY = "proxy"  # CPIMP and proxy-related issues
    SECURITY = "security"  # Private key exposure, access control
    TESTING = "testing"  # Deployment test coverage
    CONFIG = "config"  # Configuration and hardcoding issues
    DYNAMIC = "dynamic"  # On-chain verification issues


@dataclass
class Rule:
    """Base interface for all rules.

    Attributes:
        rule_id: Unique identifier (e.g., "DG-001")
        name: Human-readable name
        description: What the rule checks
        severity: Default severity level
        category: Rule category
        references: Links to documentation (OpenZeppelin docs, EIPs, blog posts)
        hack_references: Links to specific exploits, Rekt reports, incident analyses
        real_world_context: 2-4 sentence explanation of actual attacks that occurred
        remediation: How to fix the issue
    """

    rule_id: str
    name: str
    description: str
    severity: Severity
    category: RuleCategory
    references: list[str] = field(default_factory=list)
    hack_references: list[str] = field(default_factory=list)
    real_world_context: str = ""
    remediation: str = ""

    def __post_init__(self) -> None:
        """Validate rule."""
        if not self.rule_id:
            raise ValueError("Rule ID cannot be empty")
        if not self.name:
            raise ValueError("Rule name cannot be empty")


@dataclass
class RuleViolation:
    """A detected rule violation with actionable recommendation.

    Attributes:
        rule: The rule that was violated
        severity: Severity (may override rule default)
        message: Specific finding message
        recommendation: REQUIRED: How to fix this issue
        location: Source location (for static analysis)
        source_fragment: Source code fragment (for static analysis)
        storage_data: Storage slot data (for dynamic analysis)
        bytecode_data: Bytecode analysis (for dynamic analysis)
        context: Rule-specific additional context
    """

    rule: Rule
    severity: Severity
    message: str
    recommendation: str
    location: Optional[SourceLocation] = None
    source_fragment: Optional[SourceFragment] = None
    storage_data: Optional[StorageSlotResult] = None
    bytecode_data: Optional[BytecodeAnalysis] = None
    context: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate rule violation."""
        if not self.message:
            raise ValueError("Violation message cannot be empty")
        if not self.recommendation:
            raise ValueError("Recommendation is required for all violations")

