"""Tests for configuration handling."""

import tempfile
from pathlib import Path

import pytest
import yaml

from deployguard.config import DeployGuardConfig, OutputFormat
from deployguard.models.rules import Severity


class TestDeployGuardConfig:
    """Tests for DeployGuardConfig."""

    def test_default_config(self) -> None:
        """Test default configuration values."""
        config = DeployGuardConfig()
        assert config.max_file_size == 1_000_000
        assert config.timeout_seconds == 30
        assert config.rpc_timeout == 10
        assert config.rpc_retries == 3
        assert config.output_format == OutputFormat.CONSOLE
        assert config.color_enabled is True
        assert config.fail_on_severity == Severity.HIGH

    def test_config_from_dict(self) -> None:
        """Test creating config from dictionary."""
        data = {
            "analysis": {
                "max_file_size": 2_000_000,
                "timeout_seconds": 60,
            },
            "output": {
                "format": "json",
                "color": False,
            },
        }
        config = DeployGuardConfig.from_dict(data)
        assert config.max_file_size == 2_000_000
        assert config.timeout_seconds == 60
        assert config.output_format == OutputFormat.JSON
        assert config.color_enabled is False

    def test_config_from_file(self) -> None:
        """Test loading config from YAML file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            config_data = {
                "analysis": {"max_file_size": 5_000_000},
                "output": {"format": "json"},
            }
            yaml.dump(config_data, f)
            config_path = Path(f.name)

        try:
            config = DeployGuardConfig.from_file(config_path)
            assert config.max_file_size == 5_000_000
            assert config.output_format == OutputFormat.JSON
        finally:
            config_path.unlink()

    def test_config_file_not_found(self) -> None:
        """Test loading non-existent config file raises error."""
        with pytest.raises(FileNotFoundError):
            DeployGuardConfig.from_file(Path("/nonexistent/config.yaml"))

    def test_config_severity_overrides(self) -> None:
        """Test severity overrides in config."""
        data = {
            "rules": {
                "severity_overrides": {
                    "NON_ATOMIC_INIT": "low",
                    "HARDCODED_IMPL": "medium",
                }
            }
        }
        config = DeployGuardConfig.from_dict(data)
        assert config.severity_overrides["NON_ATOMIC_INIT"] == Severity.LOW
        assert config.severity_overrides["HARDCODED_IMPL"] == Severity.MEDIUM

    def test_config_discover(self) -> None:
        """Test config discovery."""
        # Should return None if no config found
        config = DeployGuardConfig.discover()
        # May be None or a config instance depending on filesystem state
        assert config is None or isinstance(config, DeployGuardConfig)

