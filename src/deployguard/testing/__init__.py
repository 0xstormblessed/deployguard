"""Test coverage analysis for deployment scripts.

This module provides functionality for analyzing test coverage of Foundry
deployment scripts.
"""

from deployguard.testing.analyzer import (
    analyze_test_coverage,
    analyze_test_coverage_from_path,
    check_script_coverage,
)
from deployguard.testing.matcher import (
    check_test_calls_run,
    find_imported_scripts,
    find_test_files,
    is_fork_test,
)

__all__ = [
    # Analyzer
    "analyze_test_coverage",
    "analyze_test_coverage_from_path",
    "check_script_coverage",
    # Matcher
    "find_test_files",
    "find_imported_scripts",
    "check_test_calls_run",
    "is_fork_test",
]
