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


def _print_finding_references(finding: Finding) -> None:
    """Print references for a finding (hack refs, docs, real-world context)."""
    # Real-world context
    if finding.real_world_context:
        console.print(f"\n  [yellow]Warning Why this matters:[/yellow]")
        console.print(f"  {finding.real_world_context}")

    # Hack references
    if finding.hack_references:
        console.print(f"\n  [red]Related Exploits:[/red]")
        for hack_ref in finding.hack_references:
            console.print(f"    - [link={hack_ref}]{hack_ref}[/link]")

    # General references
    if finding.references:
        console.print(f"\n  [blue]Documentation:[/blue]")
        for ref in finding.references:
            console.print(f"    - [link={ref}]{ref}[/link]")


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
            loc = finding.location
            file_display = ""
            if loc.file_path and Path(loc.file_path).name != file_path.name:
                file_display = f" in {Path(loc.file_path).name}"
            console.print(f"  Location: line {loc.line_number}{file_display}")
            if loc.line_content:
                console.print(f"  [dim]→ {loc.line_content}[/dim]")
        console.print(f"  {finding.description}")

        # Print hack references and real-world context
        _print_finding_references(finding)

        if finding.recommendation:
            console.print(f"\n  [dim]Recommendation: {finding.recommendation}[/dim]")
        console.print()


def _print_batch_report_console(report: BatchAnalysisReport) -> None:
    """Print batch analysis report in human + LLM readable format."""

    # Header
    console.print("=" * 80)
    console.print("[bold]DEPLOYGUARD ANALYSIS REPORT[/bold]")
    console.print("=" * 80)
    console.print()

    # Files with findings (details first)
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
                    # Show file path if it differs from the main file (e.g., inherited contracts)
                    loc = finding.location
                    file_display = ""
                    if loc.file_path:
                        try:
                            loc_file = Path(loc.file_path)
                            result_file = result.file_path
                            # Show file path if different from main file
                            if loc_file.name != result_file.name:
                                file_display = f" in {loc_file.name}"
                        except Exception:
                            pass
                    console.print(f"  Location: line {loc.line_number}{file_display}")
                    # Show line content snippet if available
                    if loc.line_content:
                        console.print(f"  [dim]→ {loc.line_content}[/dim]")

                console.print(f"  Description: {finding.description}")

                # Print hack references and real-world context
                _print_finding_references(finding)

                if finding.recommendation:
                    console.print(f"\n  [dim]Recommendation: {finding.recommendation}[/dim]")

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

    # Summary at the end
    console.print("=" * 80)
    console.print("[bold]SUMMARY[/bold]")
    console.print("=" * 80)
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
                                "line": f.location.line_number,
                                "column": f.location.column,
                            }
                            if f.location
                            else None
                        ),
                        "recommendation": f.recommendation,
                        "references": f.references,
                        "hack_references": f.hack_references,
                        "real_world_context": f.real_world_context,
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
                    rule_id=v.rule.rule_id,
                    title=v.message,
                    description=v.message,
                    severity=v.severity,
                    location=v.location,
                    recommendation=v.recommendation,
                    references=v.rule.references,
                    hack_references=v.rule.hack_references,
                    real_world_context=v.rule.real_world_context,
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
                            "references": f.references,
                            "hack_references": f.hack_references,
                            "real_world_context": f.real_world_context,
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

                        # Print hack references and real-world context
                        _print_finding_references(finding)

                        console.print(f"\n  [dim]Recommendation: {finding.recommendation}[/dim]")
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


@cli.command()
@click.argument("path", type=click.Path(exists=True), default=".")
@click.option(
    "-o",
    "--output",
    type=click.Choice(["console", "json"]),
    default="console",
    help="Output format",
)
def check(path: str, output: str) -> None:
    """Check test coverage for deployment scripts.

    PATH can be a Foundry project directory (defaults to current directory).

    Examples:
        deployguard check
        deployguard check ./my-project
        deployguard check -o json
    """
    from deployguard.testing.analyzer import analyze_test_coverage_from_path

    try:
        analysis = analyze_test_coverage_from_path(path)

        if not analysis:
            console.print("[red]Error:[/red] No Foundry project found at this path")
            console.print("[dim]Make sure you're in a directory with foundry.toml[/dim]")
            sys.exit(1)

        if output == "json":
            # JSON output
            result = {
                "project_root": str(analysis.project_root),
                "total_scripts": len(analysis.deploy_scripts),
                "scripts_with_tests": analysis.scripts_with_tests,
                "scripts_without_tests": analysis.scripts_without_tests,
                "scripts_with_fork_tests": analysis.scripts_with_fork_tests,
                "coverage": [
                    {
                        "script": str(script.relative_to(analysis.project_root)),
                        "has_any_test": cov.has_any_test,
                        "has_fork_test": cov.has_fork_test,
                        "test_calls_run": cov.test_calls_run,
                        "test_files": [
                            str(f.relative_to(analysis.project_root)) for f in cov.test_files
                        ],
                    }
                    for script, cov in analysis.coverage.items()
                ],
            }
            console.print_json(data=result)
        else:
            # Console output
            console.print("\n[bold]Test Coverage Report[/bold]")
            console.print("=" * 60)
            console.print(f"Project: {analysis.project_root}")
            console.print(f"Scripts analyzed: {len(analysis.deploy_scripts)}")
            console.print()

            # Summary table
            table = Table(title="Coverage Summary")
            table.add_column("Metric", style="cyan")
            table.add_column("Count", style="magenta", justify="right")

            table.add_row("Scripts with tests", str(analysis.scripts_with_tests))
            table.add_row("Scripts without tests", str(analysis.scripts_without_tests))
            table.add_row("Scripts with fork tests", str(analysis.scripts_with_fork_tests))

            console.print(table)
            console.print()

            # Script details
            if analysis.coverage:
                console.print("[bold]Script Coverage Details[/bold]")
                console.print("-" * 60)

                for script, cov in analysis.coverage.items():
                    script_name = script.relative_to(analysis.project_root)
                    if cov.has_any_test:
                        status = "[green]✓[/green]"
                    else:
                        status = "[red]✗[/red]"

                    console.print(f"{status} {script_name}")

                    if cov.test_files:
                        for test_file in cov.test_files:
                            test_name = test_file.relative_to(analysis.project_root)
                            fork_badge = (
                                " [cyan](fork)[/cyan]" if test_file in cov.fork_tests else ""
                            )
                            run_badge = (
                                " [yellow](calls run())[/yellow]" if cov.test_calls_run else ""
                            )
                            console.print(f"    └─ {test_name}{fork_badge}{run_badge}")
                    else:
                        console.print("    [dim]No tests found[/dim]")
                    console.print()

            # Final status
            if analysis.scripts_without_tests > 0:
                console.print(
                    f"[yellow]Warning:[/yellow] {analysis.scripts_without_tests} script(s) have no test coverage"
                )
                sys.exit(1)
            else:
                console.print("[green]✓ All scripts have test coverage[/green]")
                sys.exit(0)

    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        if "--debug" in sys.argv:
            raise
        sys.exit(1)


@cli.command()
@click.option(
    "--category",
    type=click.Choice(["proxy", "security", "testing", "config", "dynamic", "all"]),
    default="all",
    help="Filter by category",
)
@click.option(
    "--severity",
    type=click.Choice(["critical", "high", "medium", "low", "info", "all"]),
    default="all",
    help="Filter by severity",
)
@click.option(
    "-o",
    "--output",
    type=click.Choice(["console", "json"]),
    default="console",
    help="Output format",
)
def rules(category: str, severity: str, output: str) -> None:
    """List all available rules.

    Examples:
        deployguard rules
        deployguard rules --category proxy
        deployguard rules --severity critical
        deployguard rules -o json
    """
    from deployguard.rules import list_all_rules
    from deployguard.models.rules import RuleCategory, Severity

    try:
        all_rules = list_all_rules()

        # Filter by category
        if category != "all":
            category_enum = RuleCategory(category)
            all_rules = {k: v for k, v in all_rules.items() if v.rule.category == category_enum}

        # Filter by severity
        if severity != "all":
            severity_enum = Severity(severity)
            all_rules = {k: v for k, v in all_rules.items() if v.rule.severity == severity_enum}

        if output == "json":
            # JSON output
            result = {
                "total_rules": len(all_rules),
                "rules": [
                    {
                        "id": rule_instance.rule.rule_id,
                        "name": rule_instance.rule.name,
                        "description": rule_instance.rule.description,
                        "severity": rule_instance.rule.severity.value,
                        "category": rule_instance.rule.category.value,
                        "references": rule_instance.rule.references,
                        "hack_references": rule_instance.rule.hack_references,
                        "real_world_context": rule_instance.rule.real_world_context,
                        "remediation": rule_instance.rule.remediation,
                    }
                    for rule_instance in all_rules.values()
                ],
            }
            console.print_json(data=result)
        else:
            # Console output
            console.print("\n[bold]Available Rules[/bold]")
            console.print("=" * 80)
            console.print(f"Total: {len(all_rules)} rules")
            console.print()

            # Group by category
            from collections import defaultdict

            by_category: dict[str, list] = defaultdict(list)
            for rule_instance in all_rules.values():
                by_category[rule_instance.rule.category.value].append(rule_instance)

            for cat_name, cat_rules in sorted(by_category.items()):
                console.print(f"\n[bold cyan]{cat_name.upper()}[/bold cyan]")
                console.print("-" * 40)

                for rule_instance in sorted(cat_rules, key=lambda r: r.rule.rule_id):
                    rule = rule_instance.rule
                    severity_color = {
                        "critical": "red",
                        "high": "orange1",
                        "medium": "yellow",
                        "low": "blue",
                        "info": "cyan",
                    }.get(rule.severity.value, "white")

                    console.print(
                        f"[bold]{rule.rule_id}[/bold] "
                        f"[{severity_color}][{rule.severity.value.upper()}][/{severity_color}]"
                    )
                    console.print(f"  {rule.name}")
                    console.print(f"  [dim]{rule.description}[/dim]")
                    console.print()

    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        if "--debug" in sys.argv:
            raise
        sys.exit(1)


def main() -> None:
    """Entry point for CLI."""
    cli()


if __name__ == "__main__":
    main()
