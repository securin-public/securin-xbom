"""Tests for xBOM CLI commands."""

from typer.testing import CliRunner

from xbom.cli import app

runner = CliRunner()


def test_bare_xbom_shows_launch_screen():
    result = runner.invoke(app, [])
    assert result.exit_code == 0
    assert "xBOM v" in result.output and "by Securin" in result.output
    assert "Quick start" in result.output
    for command in ("scan", "doctor", "validate", "version"):
        assert command in result.output


def test_short_help_flag():
    result = runner.invoke(app, ["-h"])
    assert result.exit_code == 0
    assert "Usage" in result.output
    assert "by Securin" in result.output


def test_scan_help_groups_options_and_shows_examples():
    result = runner.invoke(app, ["scan", "--help"])
    assert result.exit_code == 0
    for panel in ("What to scan", "Enrichment and trust", "Remote repositories", "Output", "Examples"):
        assert panel in result.output
    assert "xbom scan https://github.com/org/repo --branch main" in result.output


def test_version():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    # rich Console(stderr=True) writes to stderr, but CliRunner merges output
    assert "xbom" in result.output


def test_doctor_runs():
    """Doctor command should run without crashing (some tools may be missing)."""
    result = runner.invoke(app, ["doctor"])
    assert result.exit_code in (0, 1)
    assert "xBOM" in result.output


def test_scan_missing_target():
    result = runner.invoke(app, ["scan", "/nonexistent/path/abc123"])
    assert result.exit_code == 1


def test_scan_bad_bom_type():
    result = runner.invoke(app, ["scan", ".", "--bom-types", "invalid"])
    assert result.exit_code != 0
