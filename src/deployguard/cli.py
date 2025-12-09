"""CLI interface for DeployGuard."""

import sys

import click

from deployguard import __version__


@click.group()
@click.version_option(version=__version__, prog_name="deployguard")
def cli() -> None:
    """DeployGuard - Audit Foundry deployment scripts for security vulnerabilities."""
    pass


@cli.command()
@click.argument("script_path", type=click.Path(exists=True))
@click.option(
    "-o",
    "--output",
    type=click.Choice(["console", "json", "sarif"]),
    default="console",
    help="Output format",
)
def audit(script_path: str, output: str) -> None:
    """Analyze deployment script for security vulnerabilities."""
    click.echo(f"Auditing {script_path} (output: {output})")
    click.echo("⚠️  Static analyzer not yet implemented")
    sys.exit(0)


@cli.command()
@click.argument("proxy_address")
@click.option("--rpc", required=True, help="RPC endpoint URL")
@click.option("--expected", required=True, help="Expected implementation address")
def verify(proxy_address: str, rpc: str, expected: str) -> None:
    """Verify deployed proxy against expected implementation."""
    click.echo(f"Verifying {proxy_address} (expected: {expected})")
    click.echo("⚠️  Dynamic analyzer not yet implemented")
    sys.exit(0)


def main() -> None:
    """Entry point for CLI."""
    cli()


if __name__ == "__main__":
    main()

