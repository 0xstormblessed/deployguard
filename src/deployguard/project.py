"""Foundry project detection and management.

This module provides utilities for detecting and working with Foundry projects.
"""

from pathlib import Path

from deployguard.models.testing import FoundryProject

__all__ = ["FoundryProject", "detect_foundry_project"]


def detect_foundry_project(start_path: Path | str) -> FoundryProject | None:
    """Detect a Foundry project from a given path.

    This function searches for a foundry.toml file by walking up the directory
    tree from the given path.

    Args:
        start_path: Path to start searching from (file or directory)

    Returns:
        FoundryProject if found, None otherwise

    Example:
        >>> project = detect_foundry_project(Path("script/Deploy.s.sol"))
        >>> if project:
        ...     print(f"Found project at {project.root}")
        ...     print(f"Deploy scripts: {len(project.deploy_scripts)}")
    """
    if isinstance(start_path, str):
        start_path = Path(start_path)

    return FoundryProject.detect(start_path)
