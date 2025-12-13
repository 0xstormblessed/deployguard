"""Tests for batch analysis functionality."""

import pytest
from pathlib import Path
from deployguard.static.analyzer import StaticAnalyzer
from deployguard.models.report import BatchAnalysisReport, FileAnalysisResult


class TestBatchAnalysis:
    """Test batch folder analysis."""

    def test_analyze_folder_basic(self, foundry_project_path):
        """Test basic folder analysis."""
        analyzer = StaticAnalyzer()
        report = analyzer.analyze_folder(foundry_project_path)

        assert isinstance(report, BatchAnalysisReport)
        assert report.project_root == foundry_project_path
        assert len(report.files_analyzed) > 0
        assert len(report.results) == len(report.files_analyzed)

    def test_analyze_folder_report_structure(self, foundry_project_path):
        """Test batch report has correct structure."""
        analyzer = StaticAnalyzer()
        report = analyzer.analyze_folder(foundry_project_path)

        # Check report has required fields
        assert hasattr(report, "report_id")
        assert hasattr(report, "timestamp")
        assert hasattr(report, "project_root")
        assert hasattr(report, "files_analyzed")
        assert hasattr(report, "results")
        assert hasattr(report, "summary")
        assert hasattr(report, "exit_code")

        # Check summary is populated
        assert report.summary.files_analyzed == len(report.files_analyzed)

    def test_analyze_folder_results(self, foundry_project_path):
        """Test each file gets a result."""
        analyzer = StaticAnalyzer()
        report = analyzer.analyze_folder(foundry_project_path)

        # Each file should have a result
        for file_path in report.files_analyzed:
            result = next((r for r in report.results if r.file_path == file_path), None)
            assert result is not None
            assert isinstance(result, FileAnalysisResult)

    def test_analyze_folder_error_isolation(self, foundry_project_path):
        """Test that errors in one file don't stop batch analysis."""
        # Create a malformed script
        bad_script = foundry_project_path / "script" / "Bad.s.sol"
        bad_script.write_text("This is not valid Solidity!")

        analyzer = StaticAnalyzer()
        report = analyzer.analyze_folder(foundry_project_path)

        # Should have results for all files, including the bad one
        assert len(report.results) == len(report.files_analyzed)

        # Bad file should have error
        bad_result = next((r for r in report.results if r.file_path == bad_script), None)
        if bad_result:  # Only check if the bad file was included
            assert not bad_result.success
            assert bad_result.error is not None

    def test_analyze_folder_timing(self, foundry_project_path):
        """Test that timing information is recorded."""
        analyzer = StaticAnalyzer()
        report = analyzer.analyze_folder(foundry_project_path)

        # Total time should be recorded
        assert report.total_analysis_time_ms > 0

        # Each file should have timing
        for result in report.results:
            assert result.analysis_time_ms >= 0

    def test_analyze_folder_with_patterns(self, foundry_project_path):
        """Test folder analysis with include/exclude patterns."""
        # Create multiple scripts
        (foundry_project_path / "script" / "Deploy.s.sol").write_text(
            "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;"
        )
        (foundry_project_path / "script" / "Upgrade.s.sol").write_text(
            "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;"
        )

        # Analyze with exclude pattern
        analyzer = StaticAnalyzer()
        report = analyzer.analyze_folder(
            foundry_project_path, exclude_patterns=["**/Upgrade.s.sol"]
        )

        # Should not include Upgrade.s.sol
        assert not any("Upgrade.s.sol" in str(f) for f in report.files_analyzed)

    def test_progress_callback(self, foundry_project_path):
        """Test progress callback is called."""
        progress_calls = []

        def progress_callback(file, current, total):
            progress_calls.append((file, current, total))

        analyzer = StaticAnalyzer()
        report = analyzer.analyze_folder(foundry_project_path, progress_callback=progress_callback)

        # Callback should have been called for each file
        assert len(progress_calls) == len(report.files_analyzed)

        # Check callback parameters
        for file, current, total in progress_calls:
            assert isinstance(file, Path)
            assert 1 <= current <= total
            assert total == len(report.files_analyzed)

    def test_fail_fast_stops_on_error(self, foundry_project_path):
        """Test fail_fast stops analysis on first error."""
        # Create multiple scripts, with first one being malformed
        bad_script = foundry_project_path / "script" / "Bad.s.sol"
        bad_script.write_text("This is not valid Solidity!")

        good_script = foundry_project_path / "script" / "Good.s.sol"
        good_script.write_text("// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;")

        analyzer = StaticAnalyzer()
        report = analyzer.analyze_folder(foundry_project_path, fail_fast=True)

        # Should only have results for files analyzed before failure
        # At least one result (the failed one), but not all files
        assert len(report.results) >= 1
        assert any(not r.success for r in report.results)

        # When fail_fast is True, should stop after first failure
        failed_idx = next(i for i, r in enumerate(report.results) if not r.success)
        # Should have no results after the failed one (fail-fast stopped)
        assert len(report.results) == failed_idx + 1


    def test_error_context_captured(self, foundry_project_path):
        """Test that error type and traceback are captured."""
        # Create a malformed script
        bad_script = foundry_project_path / "script" / "Bad.s.sol"
        bad_script.write_text("This is not valid Solidity!")

        analyzer = StaticAnalyzer()
        report = analyzer.analyze_folder(foundry_project_path)

        # Find the failed result
        failed = next((r for r in report.results if not r.success), None)
        assert failed is not None

        # Check error context is captured
        assert failed.error is not None
        assert failed.error_type is not None

        # Error type should be a class name (string)
        assert isinstance(failed.error_type, str)
        assert len(failed.error_type) > 0

        # For solc parse errors, traceback may be None (it's a compile error, not a Python exception)
        # For Python exceptions, traceback should contain file/line information
        if failed.error_type != "ParseError" and failed.error_traceback is not None:
            assert "Traceback" in failed.error_traceback or "File" in failed.error_traceback


class TestFileAnalysisResult:
    """Test FileAnalysisResult model."""

    def test_has_findings_property(self):
        """Test has_findings property."""
        # Result with findings
        result_with = FileAnalysisResult(
            file_path=Path("test.sol"), success=True, findings=[object()]  # type: ignore
        )
        assert result_with.has_findings is True

        # Result without findings
        result_without = FileAnalysisResult(file_path=Path("test.sol"), success=True, findings=[])
        assert result_without.has_findings is False

    def test_severity_counts(self):
        """Test severity count properties."""
        from deployguard.models.report import Finding
        from deployguard.models.rules import Severity

        findings = [
            Finding(
                id="1",
                rule_id="NON_ATOMIC_INIT",
                title="Test",
                description="Test",
                severity=Severity.CRITICAL,
            ),
            Finding(
                id="2", rule_id="HARDCODED_IMPL", title="Test", description="Test", severity=Severity.HIGH
            ),
            Finding(
                id="3", rule_id="HARDCODED_IMPL", title="Test", description="Test", severity=Severity.HIGH
            ),
        ]

        result = FileAnalysisResult(file_path=Path("test.sol"), success=True, findings=findings)

        assert result.critical_count == 1
        assert result.high_count == 2
        assert result.medium_count == 0


class TestBatchAnalysisReport:
    """Test BatchAnalysisReport model."""

    def test_files_with_findings(self):
        """Test files_with_findings property."""
        from deployguard.models.report import Finding
        from deployguard.models.rules import Severity

        report = BatchAnalysisReport(report_id="test", results=[])

        # Add file with findings
        result1 = FileAnalysisResult(
            file_path=Path("test1.sol"),
            success=True,
            findings=[
                Finding(
                    id="1",
                    rule_id="NON_ATOMIC_INIT",
                    title="Test",
                    description="Test",
                    severity=Severity.HIGH,
                )
            ],
        )

        # Add file without findings
        result2 = FileAnalysisResult(file_path=Path("test2.sol"), success=True, findings=[])

        report.results = [result1, result2]

        assert len(report.files_with_findings) == 1
        assert report.files_with_findings[0] == Path("test1.sol")

    def test_files_without_findings(self):
        """Test files_without_findings property."""
        report = BatchAnalysisReport(report_id="test", results=[])

        result1 = FileAnalysisResult(file_path=Path("test1.sol"), success=True, findings=[])
        result2 = FileAnalysisResult(file_path=Path("test2.sol"), success=True, findings=[])

        report.results = [result1, result2]

        assert len(report.files_without_findings) == 2

    def test_failed_files(self):
        """Test failed_files property."""
        report = BatchAnalysisReport(report_id="test", results=[])

        result1 = FileAnalysisResult(
            file_path=Path("test1.sol"), success=False, error="Parse error"
        )
        result2 = FileAnalysisResult(file_path=Path("test2.sol"), success=True, findings=[])

        report.results = [result1, result2]

        assert len(report.failed_files) == 1
        assert report.failed_files[0] == Path("test1.sol")

    def test_status_property(self):
        """Test status property (PASSED/FAILED)."""
        from deployguard.models.report import Finding, ReportSummary
        from deployguard.models.rules import Severity

        # Report with no critical/high findings
        report_passed = BatchAnalysisReport(report_id="test", results=[])
        report_passed.summary = ReportSummary(
            total_findings=1, critical_count=0, high_count=0, medium_count=1
        )
        assert report_passed.status == "PASSED"

        # Report with critical findings
        report_failed = BatchAnalysisReport(report_id="test", results=[])
        report_failed.summary = ReportSummary(
            total_findings=1, critical_count=1, high_count=0, medium_count=0
        )
        assert report_failed.status == "FAILED"

    def test_update_summary(self):
        """Test update_summary recalculates statistics."""
        from deployguard.models.report import Finding
        from deployguard.models.rules import Severity

        report = BatchAnalysisReport(report_id="test", files_analyzed=[Path("test.sol")])

        # Add results with findings
        result = FileAnalysisResult(
            file_path=Path("test.sol"),
            success=True,
            findings=[
                Finding(
                    id="1",
                    rule_id="NON_ATOMIC_INIT",
                    title="Test",
                    description="Test",
                    severity=Severity.CRITICAL,
                ),
                Finding(
                    id="2",
                    rule_id="HARDCODED_IMPL",
                    title="Test",
                    description="Test",
                    severity=Severity.HIGH,
                ),
            ],
        )
        report.results = [result]

        # Update summary
        report.update_summary()

        assert report.summary.total_findings == 2
        assert report.summary.critical_count == 1
        assert report.summary.high_count == 1
        assert report.summary.files_analyzed == 1
        assert report.exit_code == 1  # Should fail due to critical finding
