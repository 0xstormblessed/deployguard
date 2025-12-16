"""Foundry/Forge project detection and import remapping support.

This module handles detection of Foundry projects and resolution of Foundry-style
import paths (e.g., @openzeppelin/contracts/...) using remappings.txt or foundry.toml.

Ported from solslicer-reference with adaptations for DeployGuard.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from shutil import which
from typing import Optional


class FoundryProject:
    """Handles Foundry/Forge project detection and import remapping resolution.

    This class provides functionality to:
    - Detect if a file is part of a Foundry project
    - Find the project root directory
    - Parse remappings from remappings.txt or foundry.toml
    - Resolve Foundry-style imports to actual file paths
    - Validate that dependencies exist

    Attributes:
        file_path: Path to the Solidity file being analyzed
        project_root: Root directory of the Foundry project (if detected)
        remappings: Dictionary mapping import aliases to actual paths

    Class Attributes:
        _remappings_cache: Class-level cache for remappings per project root
    """

    # Class-level cache: project_root -> remappings dict
    # Avoids repeated `forge remappings` subprocess calls for same project
    _remappings_cache: dict[str, dict[str, str]] = {}

    @classmethod
    def clear_cache(cls) -> None:
        """Clear the remappings cache.

        Useful for testing or when project dependencies change.
        """
        cls._remappings_cache.clear()

    def __init__(self, file_path: Path) -> None:
        """Initialize FoundryProject for a given Solidity file.

        Args:
            file_path: Path to the Solidity file to analyze
        """
        self.file_path = file_path.resolve()
        self.project_root: Optional[Path] = None
        self.remappings: dict[str, str] = {}
        self.solc_version: Optional[str] = None

        # Auto-detect and initialize
        if self.detect():
            self.project_root = self._find_project_root()
            if self.project_root:
                self.remappings = self._load_remappings()
                self.solc_version = self._load_solc_version()

    def detect(self) -> bool:
        """Detect if the file is part of a Foundry project.

        Checks for Foundry indicators:
        - foundry.toml file
        - remappings.txt file
        - lib/ directory (common Foundry dependency directory)

        Returns:
            True if Foundry project detected, False otherwise
        """
        root = self._find_project_root()
        if not root:
            return False

        # Check for Foundry indicators
        has_foundry_toml = (root / "foundry.toml").exists()
        has_remappings = (root / "remappings.txt").exists()
        has_lib_dir = (root / "lib").is_dir()

        return has_foundry_toml or has_remappings or has_lib_dir

    def get_project_root(self) -> Optional[Path]:
        """Get the project root directory.

        Returns:
            Path to project root, or None if not in a Foundry project
        """
        return self.project_root

    def get_remappings(self) -> dict[str, str]:
        """Get the import remappings for this project.

        Returns:
            Dictionary mapping import aliases to file paths
            Example: {"@openzeppelin/": "/abs/path/to/lib/openzeppelin-contracts/contracts/"}
        """
        return self.remappings

    def get_remappings_list(self) -> list[str]:
        """Get remappings in solc-compatible format.

        Returns:
            List of remapping strings in "alias=path" format
        """
        return [f"{alias}={path}" for alias, path in self.remappings.items()]

    def get_solc_version(self) -> Optional[str]:
        """Get the solc version specified in foundry.toml.

        Returns:
            Solc version string (e.g., "0.8.29") or None if not specified
        """
        return self.solc_version

    def check_lib_initialized(self) -> tuple[bool, list[str]]:
        """Check if lib directory exists and has initialized dependencies.

        Returns:
            Tuple of (is_initialized, empty_lib_dirs)
            - is_initialized: True if lib directory has content
            - empty_lib_dirs: List of empty/uninitialized library directories
        """
        if not self.project_root:
            return True, []

        lib_dir = self.project_root / "lib"
        if not lib_dir.exists():
            return True, []  # No lib dir means nothing to check

        empty_dirs = []
        for subdir in lib_dir.iterdir():
            if subdir.is_dir():
                # Check if directory is empty or only has hidden files
                contents = [f for f in subdir.iterdir() if not f.name.startswith(".")]
                if not contents:
                    empty_dirs.append(subdir.name)

        return len(empty_dirs) == 0, empty_dirs

    def validate_dependencies(self) -> list[str]:
        """Validate that all remapped dependency directories exist.

        Returns:
            List of missing dependency paths. Empty list if all dependencies exist.
            Each entry is a path that should exist but doesn't.
        """
        missing = []
        for alias, path in self.remappings.items():
            dep_path = Path(path.rstrip("/"))
            if not dep_path.exists():
                missing.append(path)
        return missing

    def resolve_import(self, import_path: str) -> Optional[Path]:
        """Resolve a Foundry-style import to an actual file path.

        Args:
            import_path: Import path from Solidity code (e.g., "@openzeppelin/contracts/token/ERC20/IERC20.sol")

        Returns:
            Resolved absolute path to the file, or None if not found
        """
        # Try remapping resolution first
        for alias, remapped_path in self._get_sorted_remappings():
            if import_path.startswith(alias):
                # Replace alias with actual path
                relative_part = import_path[len(alias) :]
                resolved = Path(remapped_path.rstrip("/")) / relative_part

                if resolved.exists():
                    return resolved.resolve()

        # Fallback to relative import (for backward compatibility)
        if self.project_root:
            relative_path = self.project_root / import_path
            if relative_path.exists():
                return relative_path.resolve()

        return None

    def _find_project_root(self) -> Optional[Path]:
        """Find the Foundry project root by walking up the directory tree.

        Looks for:
        - foundry.toml
        - remappings.txt
        - .git directory

        Returns:
            Path to project root, or None if not found
        """
        current = self.file_path.parent if self.file_path.is_file() else self.file_path

        # Walk up directory tree
        for parent in [current] + list(current.parents):
            # Check for Foundry indicators
            if (parent / "foundry.toml").exists():
                return parent
            if (parent / "remappings.txt").exists():
                return parent
            if (parent / ".git").is_dir():
                # Git root might be project root
                if (parent / "lib").is_dir():
                    return parent

        return None

    def _find_remappings_file(self) -> Optional[Path]:
        """Find the remappings configuration file.

        Priority order:
        1. remappings.txt (preferred)
        2. foundry.toml (fallback)

        Returns:
            Path to remappings file, or None if not found
        """
        if not self.project_root:
            return None

        # Check for remappings.txt first (priority)
        remappings_txt = self.project_root / "remappings.txt"
        if remappings_txt.exists():
            return remappings_txt

        # Fallback to foundry.toml
        foundry_toml = self.project_root / "foundry.toml"
        if foundry_toml.exists():
            return foundry_toml

        return None

    def _load_remappings(self) -> dict[str, str]:
        """Load remappings from the project configuration.

        Priority order:
        1. Check class-level cache first
        2. `forge remappings` output (if Forge CLI available) - most complete
        3. remappings.txt file (fallback)
        4. foundry.toml remappings section (last resort)

        Returns:
            Dictionary of remappings (alias -> path)
        """
        # Check cache first
        if self.project_root:
            cache_key = str(self.project_root)
            if cache_key in FoundryProject._remappings_cache:
                return FoundryProject._remappings_cache[cache_key]

        # Priority 1: Try forge CLI (most complete, auto-discovers lib/ deps)
        forge_remappings = self._get_forge_remappings()
        if forge_remappings:
            # Cache the result
            if self.project_root:
                FoundryProject._remappings_cache[str(self.project_root)] = forge_remappings
            return forge_remappings

        # Priority 2-3: Fall back to config files
        remappings_file = self._find_remappings_file()
        if not remappings_file:
            return {}

        if remappings_file.name == "remappings.txt":
            result = self._parse_remappings_txt(remappings_file)
        elif remappings_file.name == "foundry.toml":
            result = self._parse_foundry_toml(remappings_file)
        else:
            result = {}

        # Cache the result
        if self.project_root and result:
            FoundryProject._remappings_cache[str(self.project_root)] = result

        return result

    def _parse_remappings_txt(self, file_path: Path) -> dict[str, str]:
        """Parse remappings from remappings.txt file.

        Format: alias/=path/ or alias=path
        Lines starting with # are comments

        Args:
            file_path: Path to remappings.txt

        Returns:
            Dictionary of remappings
        """
        remappings: dict[str, str] = {}

        try:
            with open(file_path, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()

                    # Skip empty lines and comments
                    if not line or line.startswith("#"):
                        continue

                    # Parse remapping: alias=path or alias/=path/
                    if "=" in line:
                        parts = line.split("=", 1)
                        if len(parts) == 2:
                            alias = parts[0].strip()
                            path = parts[1].strip()

                            # Normalize path relative to project root
                            normalized_path = self._normalize_remapping_path(path)
                            remappings[alias] = normalized_path

        except Exception:
            # Silently fail - remappings are optional
            pass

        return remappings

    def _parse_foundry_toml(self, file_path: Path) -> dict[str, str]:
        """Parse remappings from foundry.toml file.

        Args:
            file_path: Path to foundry.toml

        Returns:
            Dictionary of remappings
        """
        remappings: dict[str, str] = {}

        try:
            # Try Python 3.11+ built-in tomllib
            try:
                import tomllib
            except ImportError:
                # Fallback to tomli for older Python versions
                try:
                    import tomli as tomllib  # type: ignore[import-not-found]
                except ImportError:
                    return {}

            with open(file_path, "rb") as f:
                data = tomllib.load(f)

            # Extract remappings from [profile.default] or root
            remappings_list: list[str] = []
            if "profile" in data and "default" in data["profile"]:
                remappings_list = data["profile"]["default"].get("remappings", [])
            elif "remappings" in data:
                remappings_list = data["remappings"]

            # Parse remappings list
            for remapping in remappings_list:
                if "=" in remapping:
                    parts = remapping.split("=", 1)
                    if len(parts) == 2:
                        alias = parts[0].strip()
                        path = parts[1].strip()
                        normalized_path = self._normalize_remapping_path(path)
                        remappings[alias] = normalized_path

        except Exception:
            # Silently fail - remappings are optional
            pass

        return remappings

    def _normalize_remapping_path(self, path: str) -> str:
        """Normalize a remapping path to absolute path.

        Args:
            path: Relative or absolute path from remapping

        Returns:
            Absolute normalized path as string (preserves trailing slash if present)
        """
        if not self.project_root:
            return path

        # Check if original path had trailing slash
        has_trailing_slash = path.endswith("/")

        path_obj = Path(path)

        # If already absolute, resolve it
        if path_obj.is_absolute():
            resolved = str(path_obj.resolve())
        else:
            # Resolve relative to project root
            resolved = str((self.project_root / path_obj).resolve())

        # Preserve trailing slash (important for solc remapping concatenation)
        if has_trailing_slash and not resolved.endswith("/"):
            resolved += "/"

        return resolved

    def _load_solc_version(self) -> Optional[str]:
        """Load solc version from foundry.toml.

        Returns:
            Solc version string (e.g., "0.8.29") or None if not specified
        """
        if not self.project_root:
            return None

        foundry_toml = self.project_root / "foundry.toml"
        if not foundry_toml.exists():
            return None

        try:
            # Try Python 3.11+ built-in tomllib
            try:
                import tomllib
            except ImportError:
                try:
                    import tomli as tomllib  # type: ignore[import-not-found]
                except ImportError:
                    return None

            with open(foundry_toml, "rb") as f:
                data = tomllib.load(f)

            # Check [profile.default] first, then root
            if "profile" in data and "default" in data["profile"]:
                solc = data["profile"]["default"].get("solc")
                if solc:
                    return str(solc)

            # Check root level
            if "solc" in data:
                return str(data["solc"])

        except Exception:
            pass

        return None

    def _get_sorted_remappings(self) -> list[tuple[str, str]]:
        """Get remappings sorted by alias length (longest first).

        This ensures longest prefix matching when resolving imports.

        Returns:
            List of (alias, path) tuples sorted by alias length descending
        """
        return sorted(self.remappings.items(), key=lambda x: len(x[0]), reverse=True)

    def _is_forge_available(self) -> bool:
        """Check if forge CLI is available in the system PATH.

        Returns:
            True if forge is available, False otherwise
        """
        return which("forge") is not None

    def _get_forge_remappings(self) -> dict[str, str]:
        """Get remappings by running `forge remappings` command.

        This provides the most complete and accurate remappings as Forge
        auto-discovers dependencies from lib/ directories.

        Returns:
            Dictionary of remappings (alias -> path), empty dict on failure
        """
        if not self._is_forge_available():
            return {}

        if not self.project_root:
            return {}

        try:
            result = subprocess.run(
                ["forge", "remappings"],
                capture_output=True,
                text=True,
                cwd=self.project_root,
                timeout=30,
            )

            if result.returncode == 0:
                return self._parse_remappings_output(result.stdout)

        except subprocess.TimeoutExpired:
            pass
        except Exception:
            pass

        return {}

    def _parse_remappings_output(self, output: str) -> dict[str, str]:
        """Parse remappings from `forge remappings` output.

        Format is identical to remappings.txt: alias=path (one per line)

        Args:
            output: stdout from `forge remappings` command

        Returns:
            Dictionary of remappings (alias -> normalized path)
        """
        remappings: dict[str, str] = {}

        for line in output.strip().split("\n"):
            line = line.strip()

            # Skip empty lines
            if not line:
                continue

            # Parse remapping: alias=path
            if "=" in line:
                parts = line.split("=", 1)
                if len(parts) == 2:
                    alias = parts[0].strip()
                    path = parts[1].strip()

                    # Normalize path relative to project root
                    normalized_path = self._normalize_remapping_path(path)
                    remappings[alias] = normalized_path

        return remappings
