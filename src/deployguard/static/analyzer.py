"""Static analyzer for deployment scripts.

This module provides the main entry point for static analysis of
Foundry deployment scripts.
"""

from __future__ import annotations

import time
import traceback
import uuid
from collections.abc import Callable
from pathlib import Path

from deployguard.config import DeployGuardConfig
from deployguard.models.report import BatchAnalysisReport, FileAnalysisResult, Finding
from deployguard.models.rules import RuleViolation
from deployguard.models.static import ScriptAnalysis
from deployguard.rules.executors import StaticRuleExecutor
from deployguard.scanner import scan_deployment_scripts
from deployguard.static.parsers.foundry import FoundryScriptParser

# Note: Rule definitions are now in rules/proxy/dg*.py modules
# Rules are automatically registered when modules are imported


class StaticAnalyzer:
    """Static analyzer for deployment scripts.

    Parses deployment scripts and runs static analysis rules to detect
    potential vulnerabilities and issues.
    """

    def __init__(self, config: DeployGuardConfig | None = None) -> None:
        """Initialize the static analyzer.

        Args:
            config: Optional configuration
        """
        self.config = config
        self.parser = FoundryScriptParser()

    def analyze_file(self, file_path: Path | str) -> ScriptAnalysis:
        """Analyze a deployment script file.

        Args:
            file_path: Path to the deployment script

        Returns:
            ScriptAnalysis with detected patterns
        """
        path = Path(file_path) if isinstance(file_path, str) else file_path

        if not path.exists():
            raise FileNotFoundError(f"Script file not found: {path}")

        return self.parser.parse_file(path)

    def analyze_source(self, source: str, file_path: str = "<source>") -> ScriptAnalysis:
        """Analyze deployment script source code.

        Args:
            source: Solidity source code
            file_path: Path for error reporting

        Returns:
            ScriptAnalysis with detected patterns
        """
        return self.parser.parse_source(source, file_path)

    def run_rules(self, analysis: ScriptAnalysis) -> list[RuleViolation]:
        """Run all static analysis rules from registry.

        Args:
            analysis: Parsed script analysis

        Returns:
            List of rule violations found

        Note:
            Rules are discovered from the registry and executed via StaticRuleExecutor.
            This allows new rules to be added without modifying this analyzer.
        """
        executor = StaticRuleExecutor(self.config)
        return executor.execute(analysis)

    def analyze_folder(
        self,
        path: Path | str,
        include_patterns: list[str] | None = None,
        exclude_patterns: list[str] | None = None,
        respect_gitignore: bool = True,
        fail_fast: bool = False,
        progress_callback: Callable[[Path, int, int], None] | None = None,
    ) -> BatchAnalysisReport:
        """Analyze all deployment scripts in a folder.

        This method scans for deployment scripts recursively and analyzes each one,
        isolating errors so one failure doesn't stop the batch (unless fail_fast is True).

        Args:
            path: Starting path (file or directory)
            include_patterns: Glob patterns to include
            exclude_patterns: Glob patterns to exclude
            respect_gitignore: Whether to respect .gitignore files
            fail_fast: If True, stop analysis on first file failure
            progress_callback: Optional callback(file, current, total) for progress

        Returns:
            BatchAnalysisReport with aggregated results

        Example:
            >>> analyzer = StaticAnalyzer()
            >>> report = analyzer.analyze_folder("./script")
            >>> print(f"Analyzed {len(report.files_analyzed)} files")
            >>> print(f"Status: {report.status}")
        """
        start_time = time.time()

        # Convert to Path
        if isinstance(path, str):
            path = Path(path)

        # Scan for deployment scripts
        try:
            scripts = scan_deployment_scripts(
                path=path,
                include_patterns=include_patterns,
                exclude_patterns=exclude_patterns,
                respect_gitignore=respect_gitignore,
            )
        except ValueError as e:
            # No Foundry project found
            raise ValueError(f"Failed to scan folder: {e}") from e

        # Get project root for report
        from deployguard.project import detect_foundry_project

        project = detect_foundry_project(path)
        project_root = project.root if project else path

        # Initialize report
        report = BatchAnalysisReport(
            report_id=str(uuid.uuid4()),
            project_root=project_root,
            files_analyzed=scripts,
            results=[],
        )

        # Analyze each script with error isolation
        total = len(scripts)
        for idx, script_path in enumerate(scripts, start=1):
            # Progress callback
            if progress_callback:
                progress_callback(script_path, idx, total)

            # Analyze this file
            result = self._analyze_single_file(script_path)
            report.results.append(result)

            # Stop on first failure if fail_fast is enabled
            if fail_fast and not result.success:
                break

            # Always fail fast on setup/dependency errors (affects all files)
            if not result.success and result.error and self._is_setup_error(result.error):
                break

        # Calculate total time
        end_time = time.time()
        report.total_analysis_time_ms = (end_time - start_time) * 1000

        # Update summary
        report.update_summary()

        return report

    def _analyze_single_file(self, file_path: Path) -> FileAnalysisResult:
        """Analyze a single file with error isolation.

        Args:
            file_path: Path to the script file

        Returns:
            FileAnalysisResult for this file
        """
        start_time = time.time()

        try:
            # Parse the file
            analysis = self.analyze_file(file_path)

            # Check for parse errors
            if analysis.parse_errors:
                end_time = time.time()
                return FileAnalysisResult(
                    file_path=file_path,
                    success=False,
                    findings=[],
                    error=analysis.parse_errors[0],
                    error_type="ParseError",
                    error_traceback=None,
                    analysis_time_ms=(end_time - start_time) * 1000,
                )

            # Run rules
            violations = self.run_rules(analysis)

            # Convert violations to findings
            findings = self._violations_to_findings(violations, file_path)

            # Success
            end_time = time.time()
            return FileAnalysisResult(
                file_path=file_path,
                success=True,
                findings=findings,
                error=None,
                analysis_time_ms=(end_time - start_time) * 1000,
            )

        except Exception as e:
            # Isolate error - continue with other files
            end_time = time.time()
            return FileAnalysisResult(
                file_path=file_path,
                success=False,
                findings=[],
                error=str(e),
                error_type=type(e).__name__,
                error_traceback=traceback.format_exc(),
                analysis_time_ms=(end_time - start_time) * 1000,
            )

    def _is_setup_error(self, error_message: str) -> bool:
        """Check if an error is a setup/dependency error that affects all files.

        These errors should fail fast since they'll affect every file in the project.

        Args:
            error_message: The error message to check

        Returns:
            True if this is a setup error that should fail fast
        """
        setup_error_patterns = [
            "dependencies not installed",
            "Empty lib directories",
            "forge install",
            "git submodule",
            "Run 'forge install'",
            "requires different compiler version",
        ]
        return any(pattern in error_message for pattern in setup_error_patterns)

    def _violations_to_findings(
        self, violations: list[RuleViolation], file_path: Path
    ) -> list[Finding]:
        """Convert rule violations to findings.

        Args:
            violations: List of rule violations
            file_path: Path to the file being analyzed

        Returns:
            List of Finding objects
        """
        findings = []
        for violation in violations:
            finding = Finding(
                id=str(uuid.uuid4()),
                rule_id=violation.rule.rule_id,
                title=violation.message,
                description=violation.message,
                severity=violation.severity,
                location=violation.location,
                recommendation=violation.recommendation,
                references=violation.rule.references,
                hack_references=violation.rule.hack_references,
                real_world_context=violation.rule.real_world_context,
            )
            findings.append(finding)

        return findings


def analyze_script(file_path: str, config: DeployGuardConfig | None = None) -> ScriptAnalysis:
    """Analyze a Foundry deployment script for vulnerabilities.

    Args:
        file_path: Path to deployment script (*.s.sol)
        config: Optional configuration

    Returns:
        ScriptAnalysis with detected patterns and issues

    Raises:
        FileNotFoundError: If script file doesn't exist
        ParseError: If script cannot be parsed
    """
    analyzer = StaticAnalyzer(config)
    return analyzer.analyze_file(file_path)


def run_static_rules(
    analysis: ScriptAnalysis, config: DeployGuardConfig | None = None
) -> list[RuleViolation]:
    """Run static analysis rules against parsed script.

    Args:
        analysis: Parsed script analysis
        config: Optional configuration for rule filtering

    Returns:
        List of rule violations found
    """
    analyzer = StaticAnalyzer(config)
    return analyzer.run_rules(analysis)
