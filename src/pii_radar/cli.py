"""
CLI entry point for pii-radar.

Usage:
    pii-radar scan data.csv
    pii-radar scan data/ --output json
    pii-radar scan data.csv --min-confidence 0.9 --report report.csv
    pii-radar scan data.csv --redact redacted_data.csv
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console

from pii_radar import __version__
from pii_radar.scanner import scan_file, scan_directory
from pii_radar.reporter import (
    print_summary,
    print_table,
    print_json,
    save_csv_report,
)


@click.group()
@click.version_option(version=__version__, prog_name="pii-radar")
def cli() -> None:
    """
    \b
    ██████╗ ██╗██╗      ██████╗  █████╗ ██████╗  █████╗ ██████╗
    ██╔══██╗██║██║      ██╔══██╗██╔══██╗██╔══██╗██╔══██╗██╔══██╗
    ██████╔╝██║██║█████╗██████╔╝███████║██║  ██║███████║██████╔╝
    ██╔═══╝ ██║██║╚════╝██╔══██╗██╔══██║██║  ██║██╔══██║██╔══██╗
    ██║     ██║██║      ██║  ██║██║  ██║██████╔╝██║  ██║██║  ██║
    ╚═╝     ╚═╝╚═╝      ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝

    Scan datasets for Personally Identifiable Information (PII).
    Supports CSV, JSON, and Parquet files.
    """


@cli.command()
@click.argument("target", type=click.Path(exists=True))
@click.option(
    "--output",
    "-o",
    type=click.Choice(["table", "json"], case_sensitive=False),
    default="table",
    show_default=True,
    help="Output format for scan results.",
)
@click.option(
    "--min-confidence",
    "-c",
    type=click.FloatRange(0.0, 1.0),
    default=0.0,
    show_default=True,
    help="Minimum confidence score to include (0.0–1.0).",
)
@click.option(
    "--report",
    "-r",
    type=click.Path(),
    default=None,
    help="Save matches to a CSV report file.",
)
@click.option(
    "--redact",
    type=click.Path(),
    default=None,
    help="Save a redacted copy of the input file (CSV only).",
)
@click.option(
    "--sample",
    "-s",
    type=click.IntRange(1),
    default=None,
    help="Limit scan to first N rows per file (for quick audit sampling).",
)
@click.option(
    "--fail-on-detect",
    is_flag=True,
    default=False,
    help="Exit with code 1 if any PII is found (useful for CI/CD).",
)
def scan(
    target: str,
    output: str,
    min_confidence: float,
    report: Optional[str],
    redact: Optional[str],
    sample: Optional[int],
    fail_on_detect: bool,
) -> None:
    """Scan a FILE or DIRECTORY for PII."""

    target_path = Path(target)

    try:
        if target_path.is_dir():
            results = scan_directory(target_path, min_confidence=min_confidence, sample_rows=sample)
        else:
            results = [scan_file(target_path, min_confidence=min_confidence, sample_rows=sample)]
    except (ValueError, FileNotFoundError) as exc:
        Console().print(f"[bold red]Error:[/bold red] {exc}")
        raise SystemExit(2) from exc

    # ── Output ──────────────────────────────────────────────────────────────
    print_summary(results)

    if output == "json":
        print_json(results)
    else:
        print_table(results)

    # ── Optional CSV report ─────────────────────────────────────────────────
    if report:
        report_path = Path(report)
        save_csv_report(results, report_path)
        Console().print(f"\n[green]📄 Report saved to:[/green] {report_path}")

    # ── Optional redaction ──────────────────────────────────────────────────
    if redact:
        _redact_csv(target_path, Path(redact), results)

    # ── CI/CD exit code ─────────────────────────────────────────────────────
    if fail_on_detect and any(not r.is_clean for r in results):
        Console().print("\n[bold red]❌ PII detected — failing build.[/bold red]")
        sys.exit(1)


def _redact_csv(source: Path, dest: Path, results) -> None:
    """Write a redacted copy of the CSV with PII values replaced."""
    import pandas as pd
    from pii_radar.detectors import PATTERNS

    if source.suffix.lower() != ".csv":
        Console().print("[yellow]⚠️  --redact only supports CSV files.[/yellow]")
        return

    df = pd.read_csv(source, dtype=str)
    for result in results:
        for match in result.matches:
            col = match.column
            if col in df.columns and match.pii_type in PATTERNS:
                pattern = PATTERNS[match.pii_type]
                df[col] = df[col].apply(
                    lambda v: pattern.sub("[REDACTED]", str(v))
                    if isinstance(v, str) else v
                )
    df.to_csv(dest, index=False)
    Console().print(f"[green]🔒 Redacted file saved to:[/green] {dest}")


def main() -> None:
    cli()


if __name__ == "__main__":
    main()

# JSON output mode enables CI/CD pipeline integration
