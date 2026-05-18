"""CLI entry point for mimo-code-sentinel."""

import sys
import json
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.syntax import Syntax

from sentinel.config import SentinelConfig
from sentinel.scanner.agent import ScannerAgent
from sentinel.analyzer.agent import AnalyzerAgent
from sentinel.remediation.agent import RemediationAgent


console = Console()


@click.group()
@click.version_option(version="0.1.0", prog_name="sentinel")
def main():
    """mimo-code-sentinel: Multi-agent code security scanner."""
    pass


@main.command()
@click.argument("path", type=click.Path(exists=True))
@click.option("--config", "-c", type=click.Path(), default="sentinel.yaml", help="Config file path")
@click.option("--format", "-f", "output_format", type=click.Choice(["table", "json"]), default="table")
@click.option("--output", "-o", type=click.Path(), help="Output file for JSON format")
@click.option("--severity", "-s", type=click.Choice(["info", "low", "medium", "high", "critical"]), default="medium")
@click.option("--agents", type=str, default="scanner,analyzer,remediation", help="Comma-separated agent list")
@click.option("--no-remediation", is_flag=True, help="Skip remediation agent")
def scan(path, config, output_format, output, severity, agents, no_remediation):
    """Scan a codebase for security vulnerabilities."""
    cfg = SentinelConfig.from_file(config)
    cfg.severity_threshold = severity
    agent_list = [a.strip() for a in agents.split(",")]

    console.print(Panel.fit(
        f"[bold cyan]mimo-code-sentinel[/] v0.1.0\n"
        f"Target: [green]{path}[/]\n"
        f"Agents: [yellow]{', '.join(agent_list)}[/]",
        title="🔍 Security Scan",
    ))

    # --- Agent 1: Scanner ---
    console.print("\n[bold]Agent 1: Scanner[/] — Running static analysis...")
    scanner = ScannerAgent(cfg)
    scanner_output = scanner.scan_directory(path)

    console.print(f"  Scanned [cyan]{scanner_output.files_scanned}[/] files in {scanner_output.scan_duration_ms}ms")
    console.print(f"  Found [yellow]{len(scanner_output.findings)}[/] potential issues")

    if not scanner_output.findings:
        console.print("\n[green]✅ No security issues found![/]")
        return

    if "analyzer" not in agent_list:
        _print_scanner_results(scanner_output, output_format, output)
        return

    # --- Agent 2: Analyzer ---
    console.print("\n[bold]Agent 2: Analyzer[/] — Tracing data flow & classifying...")
    analyzer = AnalyzerAgent(cfg, base_path=path)
    analyzer_output = analyzer.analyze(scanner_output)

    console.print(f"  True positives: [red]{analyzer_output.true_positives}[/]")
    console.print(f"  False positives: [green]{analyzer_output.false_positives}[/]")

    if no_remediation or "remediation" not in agent_list:
        _print_analyzer_results(analyzer_output, output_format, output)
        return

    # --- Agent 3: Remediation ---
    console.print("\n[bold]Agent 3: Remediation[/] — Generating patches...")
    remediator = RemediationAgent(cfg)
    remediation_output = remediator.remediate(analyzer_output)

    console.print(f"  Patches generated: [cyan]{len(remediation_output.patches)}[/]")

    # --- Output ---
    if output_format == "json":
        result = {
            "scanner": json.loads(scanner_output.to_json()),
            "analyzer": json.loads(analyzer_output.to_json()),
            "remediation": json.loads(remediation_output.to_json()),
        }
        json_str = json.dumps(result, indent=2)
        if output:
            Path(output).write_text(json_str)
            console.print(f"\n[green]Report saved to {output}[/]")
        else:
            print(json_str)
    else:
        _print_full_results(analyzer_output, remediation_output)


def _print_scanner_results(scanner_output, fmt, out):
    """Print scanner-only results."""
    table = Table(title="Scanner Findings", show_lines=True)
    table.add_column("Severity", style="bold")
    table.add_column("Rule", style="cyan")
    table.add_column("File", style="green")
    table.add_column("Line", justify="right")
    table.add_column("Description")

    severity_styles = {
        "critical": "bold red",
        "high": "red",
        "medium": "yellow",
        "low": "blue",
        "info": "dim",
    }

    for f in scanner_output.findings:
        style = severity_styles.get(f.severity.value, "")
        table.add_row(
            f"[{style}]{f.severity.value.upper()}[/]",
            f.rule_id,
            f.file_path,
            str(f.line_start),
            f.description[:80],
        )
    console.print(table)


def _print_analyzer_results(analyzer_output, fmt, out):
    """Print analyzer results."""
    table = Table(title="Analyzed Findings", show_lines=True)
    table.add_column("Verdict", style="bold")
    table.add_column("Risk", style="bold")
    table.add_column("CWE")
    table.add_column("File", style="green")
    table.add_column("Confidence", justify="right")
    table.add_column("Attack Scenario")

    for f in analyzer_output.enriched_findings:
        verdict = "[red]TRUE POS[/]" if f.is_true_positive else "[green]FALSE POS[/]"
        risk_style = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "blue"}.get(f.risk_rating, "")
        table.add_row(
            verdict,
            f"[{risk_style}]{f.risk_rating.upper()}[/]",
            f.finding.cwe,
            f"{f.finding.file_path}:{f.finding.line_start}",
            f"{f.confidence_score:.0%}",
            f.attack_scenario[:80] + "..." if len(f.attack_scenario) > 80 else f.attack_scenario,
        )
    console.print(table)


def _print_full_results(analyzer_output, remediation_output):
    """Print full pipeline results."""
    _print_analyzer_results(analyzer_output, "table", None)

    if remediation_output.patches:
        console.print("\n[bold]Remediation Patches:[/]")
        for i, patch in enumerate(remediation_output.patches, 1):
            console.print(Panel(
                f"[bold]File:[/] {patch.file_path}\n"
                f"[bold]Explanation:[/] {patch.explanation}\n\n"
                f"[bold]Diff:[/]\n"
                f"{Syntax(patch.diff, 'diff', theme='monokai', line_numbers=False)}\n\n"
                f"[bold]Prevention:[/] {patch.prevention_notes}",
                title=f"Patch #{i}",
                border_style="cyan",
            ))

    console.print(Panel(remediation_output.summary, title="📊 Summary", border_style="green"))


@main.command()
@click.argument("path", type=click.Path(exists=True))
def init(path):
    """Initialize sentinel.yaml config in a project directory."""
    config_path = Path(path) / "sentinel.yaml"
    if config_path.exists():
        console.print(f"[yellow]sentinel.yaml already exists in {path}[/]")
        return
    config_path.write_text(
        "# mimo-code-sentinel configuration\n"
        "model: mimo-v2.5-pro\n"
        "severity_threshold: medium\n"
        "max_file_size_kb: 500\n"
        "exclude_patterns:\n"
        '  - "*/test/*"\n'
        '  - "*/node_modules/*"\n'
        '  - "*.min.js"\n'
    )
    console.print(f"[green]✅ Created {config_path}[/]")


if __name__ == "__main__":
    main()
