#!/usr/bin/env python3
"""CLI for generating policy compliance reports"""

import json
import sys
from pathlib import Path

import click

from .generators.csv_report import CSVReportGenerator
from .generators.html_report import HTMLReportGenerator
from .generators.json_report import JSONReportGenerator


@click.group()
@click.version_option(version="0.1.0")
def cli():
    """Policy-as-Code Reporting CLI"""
    pass


@cli.command()
@click.option(
    "--input",
    "-i",
    "input_file",
    type=click.Path(exists=True, path_type=Path),
    required=True,
    help="Input JSON file with OPA evaluation results",
)
@click.option(
    "--output",
    "-o",
    "output_dir",
    type=click.Path(path_type=Path),
    default="reports",
    help="Output directory for reports (default: reports/)",
)
@click.option(
    "--format",
    "-f",
    "formats",
    multiple=True,
    type=click.Choice(["html", "json", "csv"], case_sensitive=False),
    default=["html"],
    help="Report formats to generate (can specify multiple)",
)
@click.option(
    "--scan-target",
    type=str,
    help="Description of what was scanned (e.g., terraform plan file)",
)
def generate(input_file: Path, output_dir: Path, formats: tuple[str], scan_target: str | None):
    """Generate policy compliance reports from OPA evaluation results"""

    # Read input file
    try:
        with input_file.open() as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        click.echo(f"Error: Invalid JSON in input file: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"Error reading input file: {e}", err=True)
        sys.exit(1)

    # Extract violations from OPA output
    violations = []
    if isinstance(data, dict):
        # Handle conftest/OPA output format
        if "results" in data:
            for result in data["results"]:
                for failure in result.get("failures", []):
                    violations.append({
                        "policy": failure.get("msg", {}).get("policy", "unknown"),
                        "resource": failure.get("msg", {}).get("resource", "unknown"),
                        "severity": failure.get("msg", {}).get("severity", "MEDIUM"),
                        "message": failure.get("msg", {}).get("message", ""),
                        "remediation": failure.get("msg", {}).get("remediation", ""),
                        "compliance": failure.get("msg", {}).get("compliance", ""),
                    })
        # Handle direct deny output
        elif "deny" in data:
            violations = list(data["deny"])

    metadata = {"scan_target": scan_target} if scan_target else {}

    # Generate reports
    generated_files = []

    if "html" in formats:
        generator = HTMLReportGenerator(output_dir)
        output_file = generator.generate(violations, metadata)
        generated_files.append(("HTML", output_file))
        click.echo(f"Generated HTML report: {output_file}")

    if "json" in formats:
        generator = JSONReportGenerator(output_dir)
        output_file = generator.generate(violations, metadata)
        generated_files.append(("JSON", output_file))
        click.echo(f"Generated JSON report: {output_file}")

    if "csv" in formats:
        generator = CSVReportGenerator(output_dir)
        output_file = generator.generate(violations, metadata)
        generated_files.append(("CSV", output_file))
        click.echo(f"Generated CSV report: {output_file}")

    # Summary
    click.echo(f"\n[OK] Generated {len(generated_files)} report(s)")
    click.echo(f"Total violations found: {len(violations)}")

    if violations:
        severity_counts = {}
        for v in violations:
            severity = v.get("severity", "UNKNOWN")
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        click.echo("\nViolations by severity:")
        for severity, count in sorted(severity_counts.items()):
            click.echo(f"  {severity}: {count}")


@cli.command()
@click.option(
    "--framework",
    "-f",
    type=click.Choice(["sox", "pci-dss", "ffiec"], case_sensitive=False),
    required=True,
    help="Compliance framework to report on",
)
@click.option(
    "--input",
    "-i",
    "input_file",
    type=click.Path(exists=True, path_type=Path),
    required=True,
    help="Input JSON file with policy violations",
)
@click.option(
    "--output",
    "-o",
    "output_dir",
    type=click.Path(path_type=Path),
    default="reports",
    help="Output directory for report",
)
def compliance(framework: str, input_file: Path, output_dir: Path):
    """Generate compliance-specific reports"""

    # Read violations
    try:
        with input_file.open() as f:
            data = json.load(f)
    except Exception as e:
        click.echo(f"Error reading input file: {e}", err=True)
        sys.exit(1)

    violations = data.get("violations", []) if isinstance(data, dict) else []

    # Filter by compliance framework
    framework_upper = framework.upper().replace("-", "_")
    filtered_violations = [
        v
        for v in violations
        if v.get("compliance", "").startswith(framework_upper) or framework.lower() in v.get("policy", "").lower()
    ]

    click.echo(f"\n{framework.upper()} Compliance Report")
    click.echo(f"Total {framework.upper()} violations: {len(filtered_violations)}")

    if filtered_violations:
        # Generate HTML report
        generator = HTMLReportGenerator(output_dir)
        metadata = {"framework": framework.upper(), "scan_target": str(input_file)}
        output_file = generator.generate(filtered_violations, metadata)
        click.echo(f"Generated compliance report: {output_file}")
    else:
        click.echo(f"[OK] No {framework.upper()} violations found!")


if __name__ == "__main__":
    cli()
