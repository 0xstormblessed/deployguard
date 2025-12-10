"""Static analysis module for deployment scripts."""

from deployguard.static.analyzer import StaticAnalyzer, analyze_script
from deployguard.static.parsers.foundry import FoundryScriptParser

__all__ = [
    "StaticAnalyzer",
    "analyze_script",
    "FoundryScriptParser",
]
