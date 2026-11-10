"""CLI integration tests using Click's test runner."""

from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from pii_radar import __version__
from pii_radar.cli import cli


def test_version():
    runner = CliRunner()
    result = runner.invoke(cli, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.output


def test_scan_csv_table_output(sample_csv: Path):
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", str(sample_csv)])
    assert result.exit_code == 0
    assert "summary" in result.output.lower() or "pii" in result.output.lower()


def test_scan_csv_json_output(sample_csv: Path):
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", str(sample_csv), "--output", "json"])
    assert result.exit_code == 0
    assert "pii" in result.output.lower()


def test_scan_clean_file_shows_all_clean(clean_csv: Path):
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", str(clean_csv)])
    assert result.exit_code == 0
    assert "clean" in result.output.lower()


def test_fail_on_detect_exits_1(sample_csv: Path):
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", str(sample_csv), "--fail-on-detect"])
    assert result.exit_code == 1


def test_fail_on_detect_exits_0_for_clean_file(clean_csv: Path):
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", str(clean_csv), "--fail-on-detect"])
    assert result.exit_code == 0


def test_report_generates_csv(sample_csv: Path, tmp_path: Path):
    report_path = tmp_path / "report.csv"
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", str(sample_csv), "--report", str(report_path)])
    assert result.exit_code == 0
    assert report_path.exists()
    content = report_path.read_text()
    assert "pii_type" in content


def test_redact_generates_sanitized_csv(sample_csv: Path, tmp_path: Path):
    redacted_path = tmp_path / "redacted.csv"
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", str(sample_csv), "--redact", str(redacted_path)])
    assert result.exit_code == 0
    assert redacted_path.exists()
    content = redacted_path.read_text()
    assert "[REDACTED]" in content


def test_sample_rows_option(sample_csv: Path):
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", str(sample_csv), "--sample", "1", "--output", "json"])
    assert result.exit_code == 0


def test_scan_unsupported_file_type_reports_clean_error(tmp_path: Path):
    target = tmp_path / "notes.txt"
    target.write_text("just some text\n", encoding="utf-8")
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", str(target)])
    assert not isinstance(result.exception, ValueError)
    assert result.exit_code == 2
    assert "Unsupported file type" in result.output
