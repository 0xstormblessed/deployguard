"""Static analyzer for deployment scripts.

This module provides the main entry point for static analysis of
Foundry deployment scripts.
"""

from __future__ import annotations

from pathlib import Path

from deployguard.config import DeployGuardConfig
from deployguard.models.rules import RuleViolation
from deployguard.models.static import ScriptAnalysis
from deployguard.rules.executors import StaticRuleExecutor
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
