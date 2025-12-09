"""Configuration handling for DeployGuard."""

import os
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional

import yaml

from deployguard.models.rules import RuleCategory, Severity


class OutputFormat(Enum):
    """Output format options."""

    CONSOLE = "console"
    JSON = "json"
    SARIF = "sarif"


@dataclass
class DeployGuardConfig:
    """Tool configuration.

    Attributes:
        max_file_size: Maximum file size to analyze (bytes)
        timeout_seconds: Analysis timeout in seconds
        rpc_timeout: RPC request timeout in seconds
        rpc_retries: Number of RPC retries
        enabled_rules: List of enabled rule IDs (empty = all)
        disabled_rules: List of disabled rule IDs
        severity_overrides: Rule ID -> Severity overrides
        custom_proxy_patterns: Custom proxy pattern regexes
        output_format: Output format
        color_enabled: Enable colored output
        verbose: Enable verbose output
        fail_on_severity: Exit non-zero threshold
    """

    max_file_size: int = 1_000_000  # 1MB default
    timeout_seconds: int = 30
    rpc_timeout: int = 10
    rpc_retries: int = 3
    enabled_rules: list[str] = field(default_factory=list)
    disabled_rules: list[str] = field(default_factory=list)
    severity_overrides: dict[str, Severity] = field(default_factory=dict)
    custom_proxy_patterns: list[str] = field(default_factory=list)
    output_format: OutputFormat = OutputFormat.CONSOLE
    color_enabled: bool = True
    verbose: bool = False
    fail_on_severity: Severity = Severity.HIGH

    @classmethod
    def from_file(cls, config_path: Path) -> "DeployGuardConfig":
        """Load configuration from YAML file.

        Args:
            config_path: Path to config file

        Returns:
            DeployGuardConfig instance

        Raises:
            FileNotFoundError: If config file doesn't exist
            yaml.YAMLError: If config file is invalid YAML
        """
        if not config_path.exists():
            raise FileNotFoundError(f"Config file not found: {config_path}")

        with open(config_path, "r") as f:
            data = yaml.safe_load(f) or {}

        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: dict) -> "DeployGuardConfig":
        """Create config from dictionary.

        Args:
            data: Configuration dictionary

        Returns:
            DeployGuardConfig instance
        """
        config = cls()

        # Analysis settings
        if "analysis" in data:
            analysis = data["analysis"]
            config.max_file_size = analysis.get("max_file_size", config.max_file_size)
            config.timeout_seconds = analysis.get("timeout_seconds", config.timeout_seconds)

        # RPC settings
        if "rpc" in data:
            rpc = data["rpc"]
            config.rpc_timeout = rpc.get("timeout", config.rpc_timeout)
            config.rpc_retries = rpc.get("retries", config.rpc_retries)

        # Rule settings
        if "rules" in data:
            rules = data["rules"]
            config.enabled_rules = rules.get("enabled", config.enabled_rules)
            config.disabled_rules = rules.get("disabled", config.disabled_rules)

            # Severity overrides
            if "severity_overrides" in rules:
                for rule_id, severity_str in rules["severity_overrides"].items():
                    try:
                        config.severity_overrides[rule_id] = Severity(severity_str.lower())
                    except ValueError:
                        pass  # Skip invalid severity

        # Custom proxy patterns
        if "proxy_patterns" in data:
            config.custom_proxy_patterns = data["proxy_patterns"]

        # Output settings
        if "output" in data:
            output = data["output"]
            format_str = output.get("format", "console")
            try:
                config.output_format = OutputFormat(format_str.lower())
            except ValueError:
                pass  # Keep default
            config.color_enabled = output.get("color", config.color_enabled)
            config.verbose = output.get("verbose", config.verbose)

        # CI/CD settings
        if "fail_on_severity" in data:
            try:
                config.fail_on_severity = Severity(data["fail_on_severity"].lower())
            except ValueError:
                pass  # Keep default

        return config

    @classmethod
    def discover(cls, start_path: Optional[Path] = None) -> Optional["DeployGuardConfig"]:
        """Discover and load configuration file.

        Searches in order:
        1. Current directory: deployguard.yaml, .deployguard.yaml
        2. Script directory (if start_path provided)
        3. User config: ~/.config/deployguard/config.yaml

        Args:
            start_path: Starting path for search (e.g., script directory)

        Returns:
            DeployGuardConfig if found, None otherwise
        """
        if start_path is None:
            start_path = Path.cwd()

        # Search locations
        search_paths = [
            Path.cwd() / "deployguard.yaml",
            Path.cwd() / ".deployguard.yaml",
        ]

        if start_path != Path.cwd():
            search_paths.extend(
                [
                    start_path / "deployguard.yaml",
                    start_path / ".deployguard.yaml",
                ]
            )

        # User config
        user_config = Path.home() / ".config" / "deployguard" / "config.yaml"
        search_paths.append(user_config)

        # Try each path
        for config_path in search_paths:
            if config_path.exists():
                try:
                    return cls.from_file(config_path)
                except Exception:
                    continue  # Try next path

        return None

    def get_default_config(self) -> "DeployGuardConfig":
        """Get default configuration.

        Returns:
            Default DeployGuardConfig instance
        """
        return DeployGuardConfig()

