"""Folder scanning for batch analysis of deployment scripts.

This module provides utilities for recursively discovering deployment scripts
in Foundry projects, respecting .gitignore patterns and custom filters.
"""

import fnmatch
from collections.abc import Sequence
from pathlib import Path

try:
    import pathspec
except ImportError:
    pathspec = None  # type: ignore

from deployguard.project import detect_foundry_project


class DeploymentScriptScanner:
    """Scans directories for deployment scripts with filtering support."""

    def __init__(
        self,
        include_patterns: Sequence[str] | None = None,
        exclude_patterns: Sequence[str] | None = None,
        respect_gitignore: bool = True,
    ):
        """Initialize scanner with filter patterns.

        Args:
            include_patterns: Glob patterns to include (e.g., ["**/*.s.sol"])
            exclude_patterns: Glob patterns to exclude (e.g., ["**/test/**"])
            respect_gitignore: Whether to respect .gitignore files
        """
        self.include_patterns = include_patterns or ["**/*.s.sol"]
        self.exclude_patterns = exclude_patterns or []
        self.respect_gitignore = respect_gitignore

    def scan(self, path: Path | str) -> list[Path]:
        """Scan for deployment scripts starting from the given path.

        This method:
        1. Detects the Foundry project root
        2. Finds all deployment scripts in the script directory
        3. Filters by .gitignore patterns (if enabled)
        4. Applies include/exclude patterns
        5. Returns sorted list of matching files

        Args:
            path: Starting path (file or directory)

        Returns:
            List of deployment script paths to analyze

        Raises:
            ValueError: If no Foundry project is found
        """
        if isinstance(path, str):
            path = Path(path)

        # Detect Foundry project
        project = detect_foundry_project(path)
        if not project:
            raise ValueError(
                f"No Foundry project found at {path}. "
                f"Ensure a foundry.toml file exists in the project root or parent directories."
            )

        # Start with all deployment scripts from the project
        scripts = project.deploy_scripts

        # Filter by .gitignore if enabled
        if self.respect_gitignore and pathspec is not None:
            scripts = self._filter_gitignored(scripts, project.root)

        # Apply custom include/exclude patterns
        scripts = self._apply_filters(scripts, project.root)

        return sorted(scripts)

    def _filter_gitignored(self, files: list[Path], project_root: Path) -> list[Path]:
        """Filter out files that match .gitignore patterns.

        Args:
            files: List of files to filter
            project_root: Root directory of the project

        Returns:
            Filtered list of files
        """
        if pathspec is None:
            # pathspec not available, skip filtering
            return files

        # Load .gitignore patterns
        gitignore_path = project_root / ".gitignore"
        if not gitignore_path.exists():
            return files

        with open(gitignore_path) as f:
            spec = pathspec.PathSpec.from_lines("gitwildmatch", f)

        # Filter files
        filtered = []
        for file in files:
            # Convert to relative path for matching
            try:
                rel_path = file.relative_to(project_root)
                if not spec.match_file(str(rel_path)):
                    filtered.append(file)
            except ValueError:
                # File is not relative to project root, keep it
                filtered.append(file)

        return filtered

    def _apply_filters(self, files: list[Path], project_root: Path) -> list[Path]:
        """Apply include/exclude glob patterns.

        Uses fnmatch for proper nested directory pattern matching.

        Args:
            files: List of files to filter
            project_root: Root directory for computing relative paths

        Returns:
            Filtered list of files
        """
        filtered = files

        # Apply include patterns (only if explicitly provided and not default)
        # Files are already *.s.sol from project detection, so only filter if narrowing
        if self.include_patterns and self.include_patterns != ["**/*.s.sol"]:
            included = []
            for file in filtered:
                # Use relative path for matching
                try:
                    rel_path = str(file.relative_to(project_root))
                except ValueError:
                    # File not relative to project root, use full path
                    rel_path = str(file)

                # Check if file matches any include pattern
                if any(fnmatch.fnmatch(rel_path, pattern) for pattern in self.include_patterns):
                    included.append(file)
            filtered = included

        # Apply exclude patterns
        if self.exclude_patterns:
            excluded = []
            for file in filtered:
                # Use relative path for matching
                try:
                    rel_path = str(file.relative_to(project_root))
                except ValueError:
                    rel_path = str(file)

                # Exclude file if it matches any exclude pattern
                if not any(fnmatch.fnmatch(rel_path, pattern) for pattern in self.exclude_patterns):
                    excluded.append(file)
            filtered = excluded

        return filtered


def scan_deployment_scripts(
    path: Path | str,
    include_patterns: Sequence[str] | None = None,
    exclude_patterns: Sequence[str] | None = None,
    respect_gitignore: bool = True,
) -> list[Path]:
    """Convenience function to scan for deployment scripts.

    Args:
        path: Starting path (file or directory)
        include_patterns: Glob patterns to include
        exclude_patterns: Glob patterns to exclude
        respect_gitignore: Whether to respect .gitignore files

    Returns:
        List of deployment script paths to analyze

    Example:
        >>> scripts = scan_deployment_scripts(".")
        >>> for script in scripts:
        ...     print(f"Found: {script}")
    """
    scanner = DeploymentScriptScanner(
        include_patterns=include_patterns,
        exclude_patterns=exclude_patterns,
        respect_gitignore=respect_gitignore,
    )
    return scanner.scan(path)
