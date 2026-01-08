"""Command-line interface for Log Detective.

This module provides Typer CLI commands for analyzing logs,
running demos, and launching the Streamlit UI.
"""

import logging
import subprocess
import sys
from pathlib import Path
from typing import Optional

import typer

from log_detective import __version__
from log_detective.ingest import parse_jsonl
from log_detective.detectors import run_all_detectors
from log_detective.correlate import correlate_cases
from log_detective.report import generate_alerts_json, generate_cases_json, generate_cases_md

# Create Typer app
app = typer.Typer(
    name="log-detective",
    help="SOC-Style Log Detective: Suspicious Login Detector + Case Report Generator",
    add_completion=False,
)


def setup_logging(debug: bool = False) -> None:
    """Configure logging.
    
    Args:
        debug: Enable debug level logging.
    """
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


@app.command()
def analyze(
    input: Path = typer.Option(
        ...,
        "--input", "-i",
        help="Path to JSONL log file",
        exists=True,
        file_okay=True,
        dir_okay=False,
    ),
    outdir: Path = typer.Option(
        Path("out"),
        "--outdir", "-o",
        help="Output directory for reports",
    ),
    speed_threshold: float = typer.Option(
        900,
        "--speed-threshold",
        help="Impossible travel speed threshold (km/h)",
    ),
    max_travel_hours: float = typer.Option(
        6,
        "--max-travel-hours",
        help="Max hours for travel detection",
    ),
    failure_window: int = typer.Option(
        20,
        "--failure-window",
        help="Failure chain detection window (minutes)",
    ),
    min_failures: int = typer.Option(
        8,
        "--min-failures",
        help="Min failures before success to trigger",
    ),
    case_window: float = typer.Option(
        8,
        "--case-window",
        help="Case correlation window (hours)",
    ),
    debug: bool = typer.Option(
        False,
        "--debug",
        help="Enable debug logging",
    ),
) -> None:
    """Analyze authentication logs and generate security reports.
    
    Ingests JSONL logs, runs detection algorithms, correlates alerts
    into cases, and generates JSON + Markdown reports.
    """
    setup_logging(debug)
    logger = logging.getLogger(__name__)
    
    logger.info(f"Log Detective v{__version__}")
    logger.info(f"Analyzing: {input}")
    
    # Create output directory
    outdir.mkdir(parents=True, exist_ok=True)
    logger.info(f"Output directory: {outdir}")
    
    # Step 1: Ingest
    logger.info("Step 1/4: Ingesting logs...")
    events, event_index = parse_jsonl(input)
    logger.info(f"  Parsed {len(events)} events")
    
    # Step 2: Detect
    logger.info("Step 2/4: Running detectors...")
    alerts = run_all_detectors(
        events,
        speed_threshold_kmh=speed_threshold,
        max_travel_hours=max_travel_hours,
        failure_window_minutes=failure_window,
        min_failures_same_ip=min_failures,
    )
    logger.info(f"  Generated {len(alerts)} alerts")
    
    # Step 3: Correlate
    logger.info("Step 3/4: Correlating alerts into cases...")
    cases = correlate_cases(alerts, event_index, window_hours=case_window)
    logger.info(f"  Created {len(cases)} cases")
    
    # Step 4: Generate reports
    logger.info("Step 4/4: Generating reports...")
    
    alerts_path = outdir / "alerts.json"
    cases_json_path = outdir / "cases.json"
    cases_md_path = outdir / "cases.md"
    
    generate_alerts_json(alerts, alerts_path)
    generate_cases_json(cases, cases_json_path)
    generate_cases_md(cases, cases_md_path)
    
    # Summary
    typer.echo("")
    typer.echo("=" * 60)
    typer.echo("  ANALYSIS COMPLETE")
    typer.echo("=" * 60)
    typer.echo(f"  Events parsed:    {len(events)}")
    typer.echo(f"  Alerts generated: {len(alerts)}")
    typer.echo(f"  Cases created:    {len(cases)}")
    typer.echo("")
    typer.echo("  Output files:")
    typer.echo(f"    - {alerts_path}")
    typer.echo(f"    - {cases_json_path}")
    typer.echo(f"    - {cases_md_path}")
    typer.echo("=" * 60)
    
    # Show severity breakdown
    if cases:
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for case in cases:
            severity_counts[case.overall_severity] += 1
        
        typer.echo("")
        typer.echo("  Case Severity Breakdown:")
        for sev in ["critical", "high", "medium", "low"]:
            if severity_counts[sev] > 0:
                emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}[sev]
                typer.echo(f"    {emoji} {sev.upper()}: {severity_counts[sev]}")


@app.command()
def demo() -> None:
    """Run demo analysis on sample data.
    
    Uses samples/sample_auth_logs.jsonl and outputs to out/.
    """
    setup_logging(debug=False)
    logger = logging.getLogger(__name__)
    
    # Find sample file relative to package or current directory
    sample_paths = [
        Path("samples/sample_auth_logs.jsonl"),
        Path(__file__).parent.parent.parent / "samples" / "sample_auth_logs.jsonl",
    ]
    
    sample_file = None
    for path in sample_paths:
        if path.exists():
            sample_file = path
            break
    
    if not sample_file:
        typer.echo("Error: Sample file not found. Expected at samples/sample_auth_logs.jsonl")
        typer.echo("Run from the project root directory.")
        raise typer.Exit(1)
    
    typer.echo("")
    typer.echo("🔍 SOC-Style Log Detective - DEMO MODE")
    typer.echo("")
    
    # Run analyze with defaults
    analyze(
        input=sample_file,
        outdir=Path("out"),
        speed_threshold=900,
        max_travel_hours=6,
        failure_window=20,
        min_failures=8,
        case_window=8,
        debug=False,
    )
    
    typer.echo("")
    typer.echo("📝 To view the case report:")
    typer.echo("   cat out/cases.md")
    typer.echo("")
    typer.echo("🌐 To launch the interactive UI:")
    typer.echo("   log-detective ui")


@app.command()
def ui() -> None:
    """Launch the Streamlit interactive UI."""
    # Find the UI file
    ui_paths = [
        Path("src/log_detective/ui_streamlit.py"),
        Path(__file__).parent / "ui_streamlit.py",
    ]
    
    ui_file = None
    for path in ui_paths:
        if path.exists():
            ui_file = path
            break
    
    if not ui_file:
        typer.echo("Error: UI file not found.")
        raise typer.Exit(1)
    
    typer.echo("🌐 Launching Streamlit UI...")
    typer.echo(f"   File: {ui_file}")
    typer.echo("")
    
    # Launch streamlit
    subprocess.run([sys.executable, "-m", "streamlit", "run", str(ui_file)])


@app.command()
def version() -> None:
    """Show version information."""
    typer.echo(f"Log Detective v{__version__}")


if __name__ == "__main__":
    app()
