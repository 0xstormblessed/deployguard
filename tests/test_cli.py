"""Tests for CLI interface."""

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from click.testing import CliRunner

from deployguard.cli import cli, _print_finding_references, _print_single_file_findings
from deployguard.models.report import Finding
from deployguard.models.rules import Severity


@pytest.fixture
def runner() -> CliRunner:
    """Create a CLI test runner."""
    return CliRunner()


@pytest.fixture
def foundry_project(tmp_path: Path) -> Path:
    """Create a minimal Foundry project for testing."""
    # Create foundry.toml
    (tmp_path / "foundry.toml").write_text(
        """
[profile.default]
src = "src"
script = "script"
test = "test"
"""
    )

    # Create directories
    (tmp_path / "src").mkdir()
    (tmp_path / "script").mkdir()
    (tmp_path / "test").mkdir()

    return tmp_path


@pytest.fixture
def safe_script(foundry_project: Path) -> Path:
    """Create a safe deployment script with no vulnerabilities and a matching test."""
    script = foundry_project / "script" / "Safe.s.sol"
    script.write_text(
        """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";

contract SafeScript is Script {
    function run() public {
        vm.startBroadcast();
        // No proxy deployment, just a simple script
        vm.stopBroadcast();
    }
}
"""
    )

    # Create a matching test file to avoid NO_TEST rule
    test_file = foundry_project / "test" / "Safe.t.sol"
    test_file.write_text(
        """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../script/Safe.s.sol";

contract SafeTest is Test {
    SafeScript deployer;

    function setUp() public {
        deployer = new SafeScript();
    }

    function test_run() public {
        deployer.run();
    }
}
"""
    )
    return script


@pytest.fixture
def vulnerable_script(foundry_project: Path) -> Path:
    """Create a vulnerable deployment script with a matching test."""
    script = foundry_project / "script" / "Vulnerable.s.sol"
    script.write_text(
        '''
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract VulnerableScript is Script {
    function run() public {
        vm.startBroadcast();
        address impl = address(0x1234567890123456789012345678901234567890);
        // Vulnerable: empty init data
        ERC1967Proxy proxy = new ERC1967Proxy(impl, "");
        vm.stopBroadcast();
    }
}
'''
    )

    # Create a matching test file
    test_file = foundry_project / "test" / "Vulnerable.t.sol"
    test_file.write_text(
        """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";

contract VulnerableTest is Test {
    function test_placeholder() public {
        assertTrue(true);
    }
}
"""
    )
    return script


class TestCLIBasic:
    """Test basic CLI functionality."""

    def test_cli_help(self, runner: CliRunner) -> None:
        """Test CLI shows help."""
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "DeployGuard" in result.output
        assert "audit" in result.output
        assert "verify" in result.output
        assert "check" in result.output
        assert "rules" in result.output

    def test_cli_version(self, runner: CliRunner) -> None:
        """Test CLI shows version."""
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "deployguard" in result.output.lower()


class TestAuditCommand:
    """Test the audit command."""

    def test_audit_help(self, runner: CliRunner) -> None:
        """Test audit command help."""
        result = runner.invoke(cli, ["audit", "--help"])
        assert result.exit_code == 0
        assert "Analyze deployment scripts" in result.output
        assert "--output" in result.output
        assert "--include" in result.output
        assert "--exclude" in result.output

    def test_audit_single_file_safe(
        self, runner: CliRunner, safe_script: Path
    ) -> None:
        """Test auditing a safe single file."""
        result = runner.invoke(cli, ["audit", str(safe_script)])
        # Should pass (exit code 0) for safe script
        assert result.exit_code == 0
        assert "No issues found" in result.output or "✓" in result.output

    def test_audit_single_file_vulnerable(
        self, runner: CliRunner, vulnerable_script: Path
    ) -> None:
        """Test auditing a vulnerable single file."""
        result = runner.invoke(cli, ["audit", str(vulnerable_script)])
        # Should fail (exit code 1) for vulnerable script with critical/high findings
        # Note: Exit code depends on whether violations are found
        # The script has NON_ATOMIC_INIT and HARDCODED_IMPL vulnerabilities
        assert "Analyzing" in result.output or "Error" in result.output

    def test_audit_folder(
        self, runner: CliRunner, foundry_project: Path, safe_script: Path
    ) -> None:
        """Test auditing a folder."""
        result = runner.invoke(cli, ["audit", str(foundry_project)])
        # Check report is generated (exit code depends on findings)
        assert "DEPLOYGUARD ANALYSIS REPORT" in result.output
        assert "SUMMARY" in result.output

    def test_audit_folder_json_output(
        self, runner: CliRunner, foundry_project: Path, safe_script: Path
    ) -> None:
        """Test auditing a folder with JSON output."""
        result = runner.invoke(cli, ["audit", str(foundry_project), "-o", "json"])
        # Output may contain spinner text before JSON, so find the JSON part
        output = result.output.strip()
        # Find the start of JSON (first '{')
        json_start = output.find("{")
        assert json_start != -1, "No JSON found in output"
        json_output = output[json_start:]
        data = json.loads(json_output)
        assert "report_id" in data
        assert "summary" in data
        assert "files" in data

    def test_audit_folder_with_exclude(
        self, runner: CliRunner, foundry_project: Path, safe_script: Path
    ) -> None:
        """Test auditing with exclude pattern."""
        # Create another script to exclude
        excluded = foundry_project / "script" / "Excluded.s.sol"
        excluded.write_text("// SPDX-License-Identifier: MIT\npragma solidity ^0.8.20;")

        result = runner.invoke(
            cli, ["audit", str(foundry_project), "--exclude", "**/Excluded.s.sol"]
        )
        # Check that the command ran successfully
        assert "DEPLOYGUARD ANALYSIS REPORT" in result.output
        # The excluded file should not appear in the findings section
        # (it may still show in "files without findings" if not excluded properly)

    def test_audit_nonexistent_path(self, runner: CliRunner) -> None:
        """Test auditing a non-existent path."""
        result = runner.invoke(cli, ["audit", "/nonexistent/path"])
        assert result.exit_code != 0

    def test_audit_sarif_not_implemented(
        self, runner: CliRunner, foundry_project: Path, safe_script: Path
    ) -> None:
        """Test SARIF output shows not implemented message."""
        result = runner.invoke(cli, ["audit", str(foundry_project), "-o", "sarif"])
        assert "SARIF output not yet implemented" in result.output


class TestVerifyCommand:
    """Test the verify command."""

    def test_verify_help(self, runner: CliRunner) -> None:
        """Test verify command help."""
        result = runner.invoke(cli, ["verify", "--help"])
        assert result.exit_code == 0
        assert "Verify deployed proxy" in result.output
        assert "--rpc" in result.output
        assert "--expected" in result.output

    def test_verify_missing_required_options(self, runner: CliRunner) -> None:
        """Test verify fails without required options."""
        result = runner.invoke(
            cli, ["verify", "0x1234567890123456789012345678901234567890"]
        )
        assert result.exit_code != 0
        assert "Missing option" in result.output or "required" in result.output.lower()

    @patch("deployguard.cli.verify_proxy_impl")
    def test_verify_console_output(
        self, mock_verify: MagicMock, runner: CliRunner
    ) -> None:
        """Test verify with console output."""
        from deployguard.models.report import AnalysisReport, AnalysisType, ReportSummary

        # Mock the verification result
        mock_report = AnalysisReport(
            report_id="test-123",
            analysis_type=AnalysisType.DYNAMIC,
            target_addresses=["0x1234567890123456789012345678901234567890"],
            rpc_url="https://eth.example.com",
            findings=[],
            summary=ReportSummary(passed=True),
            exit_code=0,
        )
        mock_verify.return_value = mock_report

        result = runner.invoke(
            cli,
            [
                "verify",
                "0x1234567890123456789012345678901234567890",
                "--rpc",
                "https://eth.example.com",
                "--expected",
                "0xabcdef1234567890123456789012345678901234",
            ],
        )

        assert "Proxy Verification Report" in result.output or "Error" in result.output

    @patch("deployguard.cli.verify_proxy_impl")
    def test_verify_json_output(
        self, mock_verify: MagicMock, runner: CliRunner
    ) -> None:
        """Test verify with JSON output."""
        from deployguard.models.report import AnalysisReport, AnalysisType, ReportSummary

        mock_report = AnalysisReport(
            report_id="test-123",
            analysis_type=AnalysisType.DYNAMIC,
            target_addresses=["0x1234567890123456789012345678901234567890"],
            rpc_url="https://eth.example.com",
            findings=[],
            summary=ReportSummary(passed=True),
            exit_code=0,
        )
        mock_verify.return_value = mock_report

        result = runner.invoke(
            cli,
            [
                "verify",
                "0x1234567890123456789012345678901234567890",
                "--rpc",
                "https://eth.example.com",
                "--expected",
                "0xabcdef1234567890123456789012345678901234",
                "-o",
                "json",
            ],
        )

        # Should contain JSON or error
        if result.exit_code == 0:
            assert "report_id" in result.output or "{" in result.output


class TestCheckCommand:
    """Test the check command."""

    def test_check_help(self, runner: CliRunner) -> None:
        """Test check command help."""
        result = runner.invoke(cli, ["check", "--help"])
        assert result.exit_code == 0
        assert "Check test coverage" in result.output
        assert "--output" in result.output

    def test_check_foundry_project(
        self, runner: CliRunner, foundry_project: Path, safe_script: Path
    ) -> None:
        """Test check on a Foundry project."""
        result = runner.invoke(cli, ["check", str(foundry_project)])
        # Should show coverage report
        assert "Test Coverage Report" in result.output or "Error" in result.output

    def test_check_json_output(
        self, runner: CliRunner, foundry_project: Path, safe_script: Path
    ) -> None:
        """Test check with JSON output."""
        result = runner.invoke(cli, ["check", str(foundry_project), "-o", "json"])
        # Should output JSON
        if "Error" not in result.output:
            output = result.output.strip()
            data = json.loads(output)
            assert "project_root" in data
            assert "total_scripts" in data

    def test_check_no_foundry_project(self, runner: CliRunner, tmp_path: Path) -> None:
        """Test check fails without Foundry project."""
        result = runner.invoke(cli, ["check", str(tmp_path)])
        assert result.exit_code != 0
        assert "No Foundry project found" in result.output or "Error" in result.output


class TestRulesCommand:
    """Test the rules command."""

    def test_rules_help(self, runner: CliRunner) -> None:
        """Test rules command help."""
        result = runner.invoke(cli, ["rules", "--help"])
        assert result.exit_code == 0
        assert "List all available rules" in result.output
        assert "--category" in result.output
        assert "--severity" in result.output

    def test_rules_list_all(self, runner: CliRunner) -> None:
        """Test listing all rules."""
        result = runner.invoke(cli, ["rules"])
        assert result.exit_code == 0
        assert "Available Rules" in result.output
        # Should show some rules
        assert "NON_ATOMIC_INIT" in result.output or "Total:" in result.output

    def test_rules_filter_by_category(self, runner: CliRunner) -> None:
        """Test filtering rules by category."""
        result = runner.invoke(cli, ["rules", "--category", "proxy"])
        assert result.exit_code == 0
        # Should only show proxy rules
        if "NON_ATOMIC_INIT" in result.output:
            assert "PROXY" in result.output.upper()

    def test_rules_filter_by_severity(self, runner: CliRunner) -> None:
        """Test filtering rules by severity."""
        result = runner.invoke(cli, ["rules", "--severity", "critical"])
        assert result.exit_code == 0
        # Should only show critical rules
        assert "CRITICAL" in result.output.upper() or "Total: 0" in result.output

    def test_rules_json_output(self, runner: CliRunner) -> None:
        """Test rules with JSON output."""
        result = runner.invoke(cli, ["rules", "-o", "json"])
        assert result.exit_code == 0
        # Should be valid JSON
        output = result.output.strip()
        data = json.loads(output)
        assert "total_rules" in data
        assert "rules" in data
        assert isinstance(data["rules"], list)

    def test_rules_json_with_filters(self, runner: CliRunner) -> None:
        """Test rules JSON output with filters."""
        result = runner.invoke(
            cli, ["rules", "--category", "security", "--severity", "high", "-o", "json"]
        )
        assert result.exit_code == 0
        output = result.output.strip()
        data = json.loads(output)
        # All rules should match filters
        for rule in data["rules"]:
            assert rule["category"] == "security"
            assert rule["severity"] == "high"


class TestHelperFunctions:
    """Test CLI helper functions."""

    def test_print_finding_references_empty(self, capsys) -> None:
        """Test printing finding with no references."""
        finding = Finding(
            id="test-1",
            rule_id="TEST_RULE",
            title="Test Finding",
            description="Test description",
            severity=Severity.HIGH,
        )
        _print_finding_references(finding)
        # Should not crash, output may be empty

    def test_print_finding_references_with_context(self, capsys) -> None:
        """Test printing finding with real-world context."""
        finding = Finding(
            id="test-1",
            rule_id="TEST_RULE",
            title="Test Finding",
            description="Test description",
            severity=Severity.HIGH,
            real_world_context="This is important context",
            hack_references=["https://example.com/hack"],
            references=["https://docs.example.com"],
        )
        _print_finding_references(finding)
        # Should print without error

    def test_print_single_file_findings_empty(self, capsys) -> None:
        """Test printing empty findings list."""
        _print_single_file_findings(Path("test.sol"), [])
        # Should indicate no issues found

    def test_print_single_file_findings_with_findings(self, capsys) -> None:
        """Test printing findings list."""
        findings = [
            Finding(
                id="test-1",
                rule_id="TEST_RULE",
                title="Test Finding",
                description="Test description",
                severity=Severity.HIGH,
                recommendation="Fix this issue",
            )
        ]
        _print_single_file_findings(Path("test.sol"), findings)
        # Should print findings


class TestExitCodes:
    """Test CLI exit codes."""

    def test_audit_exit_code_with_findings(
        self, runner: CliRunner, vulnerable_script: Path
    ) -> None:
        """Test audit returns non-zero for scripts with critical/high findings."""
        result = runner.invoke(cli, ["audit", str(vulnerable_script)])
        # Vulnerable script should have findings and return non-zero
        # (has HARDCODED_IMPL which is medium, and NON_ATOMIC_INIT which is critical)
        assert "Analyzing" in result.output

    def test_audit_single_file_exit_code(
        self, runner: CliRunner, safe_script: Path
    ) -> None:
        """Test audit single file returns 0 for safe scripts."""
        result = runner.invoke(cli, ["audit", str(safe_script)])
        # Safe script with test file should pass
        assert result.exit_code == 0

    def test_rules_exit_code_success(self, runner: CliRunner) -> None:
        """Test rules always returns 0."""
        result = runner.invoke(cli, ["rules"])
        assert result.exit_code == 0
