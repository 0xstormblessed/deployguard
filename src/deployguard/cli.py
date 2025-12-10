"""CLI interface for DeployGuard."""

import asyncio
import json
import sys

import click
from rich.console import Console
from rich.table import Table

from deployguard import __version__
from deployguard.dynamic.analyzer import verify_proxy as verify_proxy_impl
from deployguard.models.core import Address

console = Console()


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
@click.option("--admin", help="Expected admin address (optional)")
@click.option(
    "-o",
    "--output",
    type=click.Choice(["console", "json"]),
    default="console",
    help="Output format",
)
def verify(proxy_address: str, rpc: str, expected: str, admin: str | None, output: str) -> None:
    """Verify deployed proxy against expected implementation."""

    async def run_verification() -> int:
        try:
            report = await verify_proxy_impl(
                Address(proxy_address),
                Address(expected),
                rpc,
                expected_admin=Address(admin) if admin else None,
            )

            if output == "json":
                # JSON output
                report_dict = {
                    "report_id": report.report_id,
                    "analysis_type": report.analysis_type.value,
                    "target_addresses": report.target_addresses,
                    "rpc_url": report.rpc_url,
                    "summary": {
                        "total_findings": report.summary.total_findings,
                        "critical": report.summary.critical_count,
                        "high": report.summary.high_count,
                        "medium": report.summary.medium_count,
                        "low": report.summary.low_count,
                        "info": report.summary.info_count,
                        "passed": report.summary.passed,
                    },
                    "findings": [
                        {
                            "id": f.id,
                            "rule_id": f.rule_id,
                            "title": f.title,
                            "severity": f.severity.value,
                            "description": f.description,
                            "recommendation": f.recommendation,
                            "on_chain_evidence": f.on_chain_evidence,
                        }
                        for f in report.findings
                    ],
                }
                console.print_json(data=report_dict)
            else:
                # Console output
                console.print(f"\n[bold]Proxy Verification Report[/bold]")
                console.print(f"Proxy: {proxy_address}")
                console.print(f"Expected Implementation: {expected}")
                if admin:
                    console.print(f"Expected Admin: {admin}")
                console.print()

                # Summary table
                table = Table(title="Summary")
                table.add_column("Severity", style="cyan")
                table.add_column("Count", style="magenta")

                table.add_row("Critical", str(report.summary.critical_count))
                table.add_row("High", str(report.summary.high_count))
                table.add_row("Medium", str(report.summary.medium_count))
                table.add_row("Low", str(report.summary.low_count))
                table.add_row("Info", str(report.summary.info_count))
                table.add_row("[bold]Total[/bold]", f"[bold]{report.summary.total_findings}[/bold]")

                console.print(table)
                console.print()

                # Findings
                if report.findings:
                    console.print("[bold red]Findings:[/bold red]")
                    for finding in report.findings:
                        severity_color = {
                            "critical": "red",
                            "high": "orange1",
                            "medium": "yellow",
                            "low": "blue",
                            "info": "cyan",
                        }.get(finding.severity.value, "white")

                        console.print(
                            f"\n[{severity_color}]● {finding.rule_id}[/{severity_color}] "
                            f"[bold]{finding.title}[/bold]"
                        )
                        console.print(
                            f"  Severity: [{severity_color}]{finding.severity.value}[/{severity_color}]"
                        )
                        console.print(f"  {finding.description}")
                        console.print(f"  [dim]→ {finding.recommendation}[/dim]")
                else:
                    console.print("[bold green]✓ No issues found[/bold green]")

                console.print()
                if report.summary.passed:
                    console.print("[bold green]✓ Verification PASSED[/bold green]")
                else:
                    console.print("[bold red]✗ Verification FAILED[/bold red]")

            return report.exit_code

        except Exception as e:
            console.print(f"[bold red]Error:[/bold red] {e}")
            return 1

    exit_code = asyncio.run(run_verification())
    sys.exit(exit_code)


def main() -> None:
    """Entry point for CLI."""
    cli()


if __name__ == "__main__":
    main()
