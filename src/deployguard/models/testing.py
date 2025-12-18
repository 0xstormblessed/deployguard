"""Test coverage data models for DeployGuard.

This module defines data structures for representing test coverage
information for deployment scripts in Foundry projects.
"""

from dataclasses import dataclass
from pathlib import Path


@dataclass
class ScriptTestCoverage:
    """Test coverage information for a deployment script."""

    deploy_script: Path
    test_files: list[Path]

    # Coverage flags
    has_any_test: bool
    has_fork_test: bool
    test_calls_run: bool

    # Details
    importing_tests: list[Path]  # Tests that import this script
    fork_tests: list[Path]       # Tests that use fork mode


@dataclass
class CoverageAnalysis:
    """Complete test analysis for a Foundry project."""

    project_root: Path

    # All deployment scripts found
    deploy_scripts: list[Path]

    # All test files found
    test_files: list[Path]

    # Coverage mapping
    coverage: dict[Path, ScriptTestCoverage]  # deploy_script → coverage

    # Summary
    scripts_with_tests: int
    scripts_without_tests: int
    scripts_with_fork_tests: int


@dataclass
class FoundryProject:
    """Represents a Foundry project structure."""

    root: Path
    config_file: Path          # foundry.toml

    # Directories (from config or defaults)
    src_dir: Path              # Default: src/
    script_dir: Path           # Default: script/
    test_dir: Path             # Default: test/

    # Detected files
    deploy_scripts: list[Path]
    test_files: list[Path]

    @classmethod
    def detect(cls, start_path: Path) -> "FoundryProject | None":
        """Detect Foundry project from a path.

        Args:
            start_path: Path to start searching from (file or directory)

        Returns:
            FoundryProject if found, None otherwise
        """
        # Resolve to absolute path first - relative paths don't walk up correctly
        # because Path(".").parent == Path("."), causing the loop to exit early
        start_path = start_path.resolve()
        # Walk up to find foundry.toml
        current = start_path if start_path.is_dir() else start_path.parent
        while current != current.parent:
            config = current / "foundry.toml"
            if config.exists():
                return cls._from_config(config)
            current = current.parent
        return None

    @classmethod
    def _from_config(cls, config_file: Path) -> "FoundryProject":
        """Parse foundry.toml and create project.

        Args:
            config_file: Path to foundry.toml

        Returns:
            FoundryProject instance
        """
        try:
            import tomli
        except ImportError:
            import tomllib as tomli  # Python 3.11+

        root = config_file.parent
        with open(config_file, "rb") as f:
            config = tomli.load(f)

        # Get directories from config or use defaults
        profile = config.get("profile", {}).get("default", {})
        src_dir = root / profile.get("src", "src")
        script_dir = root / profile.get("script", "script")
        test_dir = root / profile.get("test", "test")

        # Find deployment scripts
        deploy_scripts = list(script_dir.glob("**/*.s.sol")) if script_dir.exists() else []

        # Find test files
        test_files = list(test_dir.glob("**/*.t.sol")) if test_dir.exists() else []

        return cls(
            root=root,
            config_file=config_file,
            src_dir=src_dir,
            script_dir=script_dir,
            test_dir=test_dir,
            deploy_scripts=deploy_scripts,
            test_files=test_files,
        )
