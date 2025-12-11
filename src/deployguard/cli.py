"""CLI interface for DeployGuard."""

import asyncio
import sys
import uuid
from pathlib import Path

import click
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from deployguard import __version__
from deployguard.config import DeployGuardConfig
from deployguard.dynamic.analyzer import verify_proxy as verify_proxy_impl
from deployguard.models.core import Address
from deployguard.models.report import BatchAnalysisReport, Finding
from deployguard.static.analyzer import StaticAnalyzer

console = Console()


def _print_single_file_findings(file_path: Path, findings: list) -> None:
    """Print findings for a single file."""
    if not findings:
        console.print(f"\n[bold green]✓ No issues found in {file_path.name}[/bold green]\n")
        return

    console.print(f"\n[bold]Findings in {file_path}:[/bold]\n")
    for finding in findings:
        severity_color = {
            "critical": "red",
            "high": "orange1",
            "medium": "yellow",
            "low": "blue",
            "info": "cyan",
        }.get(finding.severity.value, "white")

        console.print(
            f"[{severity_color}][{finding.severity.value.upper()}][/{severity_color}] "
            f"[bold]{finding.rule_id}: {finding.title}[/bold]"
        )
        if finding.location:
            console.print(f"  Location: line {finding.location.line}")
        console.print(f"  {finding.description}")
        if finding.recommendation:
            console.print(f"  [dim]→ {finding.recommendation}[/dim]")
        console.print()


def _print_batch_report_console(report: BatchAnalysisReport) -> None:
    """Print batch analysis report in human + LLM readable format."""

    # Header
    console.print("=" * 80)
    console.print("[bold]DEPLOYGUARD ANALYSIS REPORT[/bold]")
    console.print("=" * 80)
    console.print()

    # Summary
    console.print("[bold]SUMMARY[/bold]")
    console.print("-" * 80)
    console.print(f"Files scanned: {len(report.files_analyzed)}")
    console.print(f"Files with findings: {len(report.files_with_findings)}")
    console.print(
        f"Total findings: {report.summary.total_findings} "
        f"({report.summary.critical_count} critical, "
        f"{report.summary.high_count} high, "
        f"{report.summary.medium_count} medium, "
        f"{report.summary.low_count} low, "
        f"{report.summary.info_count} info)"
    )
    status_color = "green" if report.status == "PASSED" else "red"
    console.print(f"Status: [{status_color}]{report.status}[/{status_color}]")
    console.print()

    # Files with findings
    if report.files_with_findings:
        for result in report.results:
            if not result.has_findings:
                continue

            console.print("=" * 80)
            console.print(f"[bold]FILE: {result.file_path.relative_to(report.project_root)}[/bold]")
            console.print("=" * 80)
            console.print()

            for finding in result.findings:
                severity_color = {
                    "critical": "red",
                    "high": "orange1",
                    "medium": "yellow",
                    "low": "blue",
                    "info": "cyan",
                }.get(finding.severity.value, "white")

                console.print(
                    f"[{severity_color}][{finding.severity.value.upper()}][/{severity_color}] "
                    f"[bold]{finding.rule_id}: {finding.title}[/bold]"
                )

                if finding.location:
                    console.print(f"  Location: line {finding.location.line}")

                console.print(f"  Description: {finding.description}")

                if finding.recommendation:
                    console.print(f"  Recommendation: {finding.recommendation}")

                console.print()

    # Files without findings
    if report.files_without_findings:
        console.print("=" * 80)
        console.print(f"[bold]FILES WITH NO FINDINGS ({len(report.files_without_findings)})[/bold]")
        console.print("=" * 80)
        for file_path in report.files_without_findings:
            console.print(f"- {file_path.relative_to(report.project_root)}")
        console.print()

    # Failed files
    if report.failed_files:
        console.print("=" * 80)
        console.print(f"[bold red]FAILED ANALYSES ({len(report.failed_files)})[/bold red]")
        console.print("=" * 80)
        for result in report.results:
            if not result.success:
                console.print(f"[red]✗ {result.file_path.relative_to(report.project_root)}[/red]")
                console.print(f"  Error: {result.error}")
        console.print()

    # Footer
    console.print("=" * 80)
    console.print("[bold]END OF REPORT[/bold]")
    console.print("=" * 80)


def _print_batch_report_json(report: BatchAnalysisReport) -> None:
    """Print batch analysis report in JSON format."""
    report_dict = {
        "report_id": report.report_id,
        "timestamp": report.timestamp.isoformat(),
        "tool_version": report.tool_version,
        "project_root": str(report.project_root),
        "summary": {
            "files_scanned": len(report.files_analyzed),
            "files_with_findings": len(report.files_with_findings),
            "files_without_findings": len(report.files_without_findings),
            "total_findings": report.summary.total_findings,
            "critical": report.summary.critical_count,
            "high": report.summary.high_count,
            "medium": report.summary.medium_count,
            "low": report.summary.low_count,
            "info": report.summary.info_count,
            "status": report.status,
        },
        "files": [
            {
                "path": str(result.file_path.relative_to(report.project_root)),
                "success": result.success,
                "error": result.error,
                "analysis_time_ms": result.analysis_time_ms,
                "findings": [
                    {
                        "id": f.id,
                        "rule_id": f.rule_id,
                        "title": f.title,
                        "severity": f.severity.value,
                        "description": f.description,
                        "location": (
                            {
                                "line": f.location.line,
                                "column": f.location.column,
                            }
                            if f.location
                            else None
                        ),
                        "recommendation": f.recommendation,
                    }
                    for f in result.findings
                ],
            }
            for result in report.results
        ],
        "total_analysis_time_ms": report.total_analysis_time_ms,
    }
    console.print_json(data=report_dict)


@click.group()
@click.version_option(version=__version__, prog_name="deployguard")
def cli() -> None:
    """DeployGuard - Audit Foundry deployment scripts for security vulnerabilities."""
    pass


@cli.command()
@click.argument("path", type=click.Path(exists=True))
@click.option(
    "-o",
    "--output",
    type=click.Choice(["console", "json", "sarif"]),
    default="console",
    help="Output format",
)
@click.option(
    "--include",
    multiple=True,
    help="Glob patterns to include (e.g., '**/*.s.sol')",
)
@click.option(
    "--exclude",
    multiple=True,
    help="Glob patterns to exclude (e.g., '**/test/**')",
)
@click.option(
    "--no-gitignore",
    is_flag=True,
    help="Don't respect .gitignore patterns",
)
@click.option(
    "--fail-fast",
    is_flag=True,
    help="Stop on first analysis error",
)
def audit(
    path: str,
    output: str,
    include: tuple[str],
    exclude: tuple[str],
    no_gitignore: bool,
    fail_fast: bool,
) -> None:
    """Analyze deployment scripts for security vulnerabilities.

    PATH can be a single script file or a directory (analyzed recursively).

    Examples:
        deployguard audit script/Deploy.s.sol
        deployguard audit ./script
        deployguard audit . --include '**/*.s.sol' --exclude '**/mock/**'
    """
    try:
        # Initialize analyzer
        config = DeployGuardConfig()
        analyzer = StaticAnalyzer(config)

        # Check if path is file or directory
        path_obj = Path(path)
        is_single_file = path_obj.is_file()

        if is_single_file:
            # Single file analysis (legacy mode)
            console.print(f"[cyan]Analyzing[/cyan] {path}")
            analysis = analyzer.analyze_file(path_obj)
            violations = analyzer.run_rules(analysis)

            # Convert to findings
            findings = [
                Finding(
                    id=str(uuid.uuid4()),
                    rule_id=v.rule_id,
                    title=v.message,
                    description=v.message,
                    severity=v.severity,
                    location=v.location,
                    recommendation=v.recommendation,
                )
                for v in violations
            ]

            # Print findings
            if output == "console":
                _print_single_file_findings(path_obj, findings)
            else:
                console.print(
                    "[yellow]JSON/SARIF output for single file not yet implemented[/yellow]"
                )

            exit_code = 1 if any(f.severity.value in ["critical", "high"] for f in findings) else 0
            sys.exit(exit_code)
        else:
            # Batch folder analysis
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
            ) as progress:
                task = progress.add_task("[cyan]Scanning for deployment scripts...", total=None)

                # Analyze folder
                report = analyzer.analyze_folder(
                    path=path_obj,
                    include_patterns=list(include) if include else None,
                    exclude_patterns=list(exclude) if exclude else None,
                    respect_gitignore=not no_gitignore,
                    fail_fast=fail_fast,
                    progress_callback=lambda file, current, total: progress.update(
                        task, description=f"[cyan]Analyzing {file.name} ({current}/{total})"
                    ),
                )

                progress.update(task, description="[green]✓ Analysis complete")

            # Handle output format
            if output == "console":
                _print_batch_report_console(report)
            elif output == "json":
                _print_batch_report_json(report)
            else:
                console.print("[yellow]SARIF output not yet implemented[/yellow]")

            sys.exit(report.exit_code)

    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        if "--debug" in sys.argv:
            raise
        sys.exit(1)


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
                console.print("\n[bold]Proxy Verification Report[/bold]")
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
