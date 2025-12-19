"""DeployGuard - CLI tool for auditing Foundry deployment scripts."""

from importlib.metadata import version, PackageNotFoundError

try:
    __version__ = version("deployguard")
except PackageNotFoundError:
    __version__ = "0.0.0-dev"  # Fallback for development without install

