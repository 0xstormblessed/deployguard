"""Tests for deployment script scanner."""

import pytest
from pathlib import Path
from deployguard.scanner import DeploymentScriptScanner, scan_deployment_scripts


class TestDeploymentScriptScanner:
    """Test DeploymentScriptScanner class."""

    def test_scanner_initialization(self):
        """Test scanner can be initialized with default patterns."""
        scanner = DeploymentScriptScanner()
        assert scanner.include_patterns == ["**/*.s.sol"]
        assert scanner.exclude_patterns == []
        assert scanner.respect_gitignore is True

    def test_scanner_custom_patterns(self):
        """Test scanner accepts custom include/exclude patterns."""
        scanner = DeploymentScriptScanner(
            include_patterns=["custom/*.s.sol"],
            exclude_patterns=["**/test/**"],
            respect_gitignore=False,
        )
        assert scanner.include_patterns == ["custom/*.s.sol"]
        assert scanner.exclude_patterns == ["**/test/**"]
        assert scanner.respect_gitignore is False

    def test_scan_no_project(self, tmp_path):
        """Test scan raises error when no Foundry project found."""
        scanner = DeploymentScriptScanner()
        with pytest.raises(ValueError, match="No Foundry project found"):
            scanner.scan(tmp_path)

    def test_scan_finds_scripts(self, foundry_project_path):
        """Test scan finds deployment scripts in Foundry project."""
        scanner = DeploymentScriptScanner()
        scripts = scanner.scan(foundry_project_path)

        assert isinstance(scripts, list)
        assert all(isinstance(s, Path) for s in scripts)
        assert all(s.suffix == ".sol" for s in scripts)
        assert all(s.stem.endswith(".s") for s in scripts)

    def test_scan_exclude_patterns(self, foundry_project_path):
        """Test scan respects exclude patterns."""
        # Create a mock script in a mock directory
        mock_dir = foundry_project_path / "script" / "mock"
        mock_dir.mkdir(exist_ok=True)
        mock_script = mock_dir / "Mock.s.sol"
        mock_script.write_text("// Mock script")

        # Scan without exclude
        scanner = DeploymentScriptScanner()
        all_scripts = scanner.scan(foundry_project_path)

        # Scan with exclude
        scanner_excluded = DeploymentScriptScanner(exclude_patterns=["**/mock/**"])
        excluded_scripts = scanner_excluded.scan(foundry_project_path)

        assert len(excluded_scripts) < len(all_scripts)
        assert not any("mock" in str(s) for s in excluded_scripts)

    def test_scan_convenience_function(self, foundry_project_path):
        """Test convenience function works the same as class."""
        scripts = scan_deployment_scripts(foundry_project_path)
        assert isinstance(scripts, list)
        assert len(scripts) > 0


class TestGitignoreFiltering:
    """Test .gitignore pattern filtering."""

    def test_gitignore_respected(self, foundry_project_path):
        """Test that .gitignore patterns are respected."""
        # Create .gitignore
        gitignore = foundry_project_path / ".gitignore"
        gitignore.write_text("script/Ignored.s.sol\n")

        # Create ignored script
        ignored = foundry_project_path / "script" / "Ignored.s.sol"
        ignored.write_text("// Ignored")

        # Scan with gitignore
        scanner = DeploymentScriptScanner(respect_gitignore=True)
        scripts = scanner.scan(foundry_project_path)

        # Verify ignored file is not in results
        assert not any(s.name == "Ignored.s.sol" for s in scripts)

    def test_gitignore_disabled(self, foundry_project_path):
        """Test gitignore can be disabled."""
        # Create .gitignore
        gitignore = foundry_project_path / ".gitignore"
        gitignore.write_text("script/Ignored.s.sol\n")

        # Create ignored script
        ignored = foundry_project_path / "script" / "Ignored.s.sol"
        ignored.write_text("// Ignored")

        # Scan without gitignore
        scanner = DeploymentScriptScanner(respect_gitignore=False)
        scripts = scanner.scan(foundry_project_path)

        # Verify ignored file IS in results
        assert any(s.name == "Ignored.s.sol" for s in scripts)

    def test_no_gitignore_file(self, foundry_project_path):
        """Test scanner works when no .gitignore exists."""
        # Ensure no .gitignore
        gitignore = foundry_project_path / ".gitignore"
        if gitignore.exists():
            gitignore.unlink()

        scanner = DeploymentScriptScanner(respect_gitignore=True)
        scripts = scanner.scan(foundry_project_path)

        assert isinstance(scripts, list)


class TestSortingAndOrdering:
    """Test that results are sorted."""

    def test_results_sorted(self, foundry_project_path):
        """Test that scan results are sorted."""
        scanner = DeploymentScriptScanner()
        scripts = scanner.scan(foundry_project_path)

        # Verify sorted
        assert scripts == sorted(scripts)


class TestRelativePathScanning:
    """Test scanning from relative paths."""

    def test_scan_from_relative_subdirectory(self, foundry_project_path, monkeypatch):
        """Test scanning from relative path like 'script/' finds foundry.toml in parent.

        This reproduces a bug where running `deployguard audit script/` from within
        a Foundry project fails because relative path walk-up doesn't work correctly.
        Path(".").parent == Path("."), so the loop exits before finding foundry.toml.
        """
        # Change to the project directory
        monkeypatch.chdir(foundry_project_path)

        # Scan from relative "script/" path - this should find foundry.toml in parent
        scanner = DeploymentScriptScanner()
        scripts = scanner.scan(Path("script"))

        assert isinstance(scripts, list)
        assert len(scripts) > 0
        assert all(s.suffix == ".sol" for s in scripts)

    def test_scan_from_relative_current_dir(self, foundry_project_path, monkeypatch):
        """Test scanning from '.' relative path works."""
        monkeypatch.chdir(foundry_project_path)

        scanner = DeploymentScriptScanner()
        scripts = scanner.scan(Path("."))

        assert isinstance(scripts, list)
        assert len(scripts) > 0


class TestNestedDirectoryMatching:
    """Test path matching for nested directories."""

    def test_exclude_nested_directory(self, foundry_project_path):
        """Test that nested directory patterns work correctly."""
        # Create nested structure
        mock_dir = foundry_project_path / "script" / "mock"
        mock_dir.mkdir(exist_ok=True)
        mock_script = mock_dir / "Mock.s.sol"
        mock_script.write_text("// Mock script")

        nested_dir = foundry_project_path / "script" / "sub" / "nested"
        nested_dir.mkdir(parents=True, exist_ok=True)
        nested_script = nested_dir / "Nested.s.sol"
        nested_script.write_text("// Nested script")

        # Scan with nested directory exclude pattern
        scanner = DeploymentScriptScanner(exclude_patterns=["**/mock/**"])
        scripts = scanner.scan(foundry_project_path)

        # Should not include mock directory files
        assert not any("mock" in str(s).lower() for s in scripts)

        # Should include nested (not in mock)
        assert any("Nested.s.sol" in str(s) for s in scripts)

    def test_include_specific_subdirectory(self, foundry_project_path):
        """Test including only files from specific subdirectory."""
        # Create subdirectories
        prod_dir = foundry_project_path / "script" / "prod"
        prod_dir.mkdir(exist_ok=True)
        prod_script = prod_dir / "Prod.s.sol"
        prod_script.write_text("// Prod script")

        test_dir = foundry_project_path / "script" / "test"
        test_dir.mkdir(exist_ok=True)
        test_script = test_dir / "Test.s.sol"
        test_script.write_text("// Test script")

        # Only include prod subdirectory (use relative pattern from project root)
        scanner = DeploymentScriptScanner(include_patterns=["script/prod/*.s.sol"])
        scripts = scanner.scan(foundry_project_path)

        # Should only include prod files
        assert any("Prod.s.sol" in str(s) for s in scripts)
        assert not any("Test.s.sol" in str(s) for s in scripts)
