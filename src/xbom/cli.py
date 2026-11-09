"""xBOM CLI — Generate unified SBOM, AI-BOM, CBOM, and API-BOM."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console
from rich.padding import Padding
from rich.table import Table
from typer.core import TyperCommand, TyperGroup

from xbom import __version__
from xbom.branding import REPO_URL, header, print_launch_screen, section
from xbom.config import get_default_output_dir
from xbom.models import BomType, SbomTool, ScanConfig
from xbom.source.provider import detect_provider
from xbom.utils.subprocess import check_tool_version, find_tool


class _BrandedGroup(TyperGroup):
    """Top-level command group that puts the Securin logo above `xbom --help`."""

    def format_help(self, ctx, formatter):
        out = Console()
        for renderable in header(out):
            out.print(renderable)
        super().format_help(ctx, formatter)


app = typer.Typer(
    name="xbom",
    cls=_BrandedGroup,
    epilog=f"Run 'xbom <command> --help' for a command's options. Docs: {REPO_URL}",
    context_settings={"help_option_names": ["-h", "--help"]},
    rich_markup_mode="rich",
)
console = Console(stderr=True)

# Help panels that group the scan options
_PANEL_SCOPE = "What to scan"
_PANEL_REMOTE = "Remote repositories"
_PANEL_TRUST = "Enrichment and trust"
_PANEL_OUTPUT = "Output"

_SCAN_EXAMPLES = [
    ("xbom scan .", "Scan the current project"),
    ("xbom scan ./app --bom-types aibom,apibom", "Only the AI-BOM and API-BOM"),
    ("xbom scan https://github.com/org/repo --branch main", "Scan a branch of a remote repository"),
    ("xbom scan . --enrich --allow-build-tools", "Everything, for a project you trust"),
    ("xbom scan . --live-url https://api.example.com", "Also check a live endpoint's TLS"),
]


class _ScanCommand(TyperCommand):
    """`xbom scan` with usage examples after its options."""

    def format_help(self, ctx, formatter):
        super().format_help(ctx, formatter)
        if formatter.getvalue():
            # Rich is turned off, so help is buffered as plain text: append the examples to it
            with formatter.section("Examples"):
                formatter.write_dl(_SCAN_EXAMPLES)
        else:
            Console().print(Padding(section("Examples", _SCAN_EXAMPLES), (1, 0, 1, 1)))


@app.callback(invoke_without_command=True)
def main(ctx: typer.Context) -> None:
    # Bare `xbom` shows the launch screen instead of an error or the raw option list
    if ctx.invoked_subcommand is None:
        group = ctx.command
        commands = [
            (name, group.get_command(ctx, name).get_short_help_str(limit=70).rstrip("."))
            for name in group.list_commands(ctx)
        ]
        print_launch_screen(Console(), commands)


def _parse_bom_types(value: str | None) -> list[BomType]:
    """Parse comma-separated BOM types."""
    if not value:
        return list(BomType)
    parts = [p.strip().lower() for p in value.split(",")]
    result = []
    for p in parts:
        try:
            result.append(BomType(p))
        except ValueError:
            valid = ", ".join(bt.value for bt in BomType)
            raise typer.BadParameter(f"Unknown BOM type: '{p}'. Valid types: {valid}")
    return result


def _parse_skip(value: str | None) -> list[BomType]:
    """Parse --skip flag and return list of BOM types to skip."""
    if not value:
        return []
    return _parse_bom_types(value)


@app.command(cls=_ScanCommand)
def scan(
    target: Annotated[str, typer.Argument(
        help="Local folder or git URL (https:// or git@) to scan.", show_default=False,
    )],
    bom_types: Annotated[Optional[str], typer.Option(
        "--bom-types",
        help="BOMs to generate, comma-separated: sbom, aibom, cbom, apibom. Defaults to all four.",
        rich_help_panel=_PANEL_SCOPE,
        show_default=False,
    )] = None,
    skip: Annotated[Optional[str], typer.Option(
        "--skip",
        help="BOMs to leave out, comma-separated. Without an SBOM, the AI-BOM can't cross-check packages.",
        rich_help_panel=_PANEL_SCOPE,
        show_default=False,
    )] = None,
    sbom_tool: Annotated[SbomTool, typer.Option(
        "--sbom-tool", help="Tool that generates the SBOM.", rich_help_panel=_PANEL_SCOPE,
    )] = SbomTool.CDXGEN,
    live_url: Annotated[Optional[str], typer.Option(
        "--live-url",
        help="Also check the TLS setup of this https:// endpoint with testssl.sh (adds to the CBOM).",
        rich_help_panel=_PANEL_SCOPE,
        show_default=False,
    )] = None,
    enrich: Annotated[bool, typer.Option(
        "--enrich",
        help="Classify unknown packages with an LLM agent. Needs an API key and the 'agent' extra; see README.",
        rich_help_panel=_PANEL_TRUST,
    )] = False,
    allow_build_tools: Annotated[bool, typer.Option(
        "--allow-build-tools",
        help="Let cdxgen and the CodeGraph indexer install dependencies and run the project's build tools "
        "(mvnw, gradlew, npm/pip). Enables CodeGraph and cdxgen crypto analysis and gives a more complete SBOM, "
        "but executes code from the scanned project — trusted projects only.",
        rich_help_panel=_PANEL_TRUST,
    )] = False,
    branch: Annotated[Optional[str], typer.Option(
        "--branch",
        help="Branch to clone. Defaults to the repository's default branch.",
        rich_help_panel=_PANEL_REMOTE,
        show_default=False,
    )] = None,
    token: Annotated[Optional[str], typer.Option(
        "--token",
        help="Token for a private repository. Prefer XBOM_GITHUB_TOKEN, XBOM_GITLAB_TOKEN or XBOM_BITBUCKET_TOKEN, "
        "which stay out of your shell history.",
        rich_help_panel=_PANEL_REMOTE,
        show_default=False,
    )] = None,
    provider: Annotated[Optional[str], typer.Option(
        "--provider",
        help="Git provider for a URL target: github, gitlab, bitbucket, git. Needed for self-hosted servers "
        "to use the provider's XBOM_*_TOKEN env var.",
        rich_help_panel=_PANEL_REMOTE,
        show_default=False,
    )] = None,
    output_dir: Annotated[Optional[Path], typer.Option(
        "--output-dir", "-o",
        help="Where to write the BOMs. Defaults to ./xbom-output, or $XBOM_OUTPUT_DIR if set.",
        rich_help_panel=_PANEL_OUTPUT,
        show_default=False,
    )] = None,
    verbose: Annotated[bool, typer.Option(
        "--verbose", "-v", help="Show detailed progress from each scanner.", rich_help_panel=_PANEL_OUTPUT,
    )] = False,
) -> None:
    """Scan a project and write BOMs to ./xbom-output.

    Generates an SBOM, AI-BOM, CBOM and API-BOM for a local folder or a git repository,
    writes each one, and merges them into xbom-composite.cdx.json.
    """
    import time

    from xbom.runner import run_scan

    # Resolve BOM types
    selected = _parse_bom_types(bom_types)
    skipped = _parse_skip(skip)
    final_types = [bt for bt in selected if bt not in skipped]

    config = ScanConfig(
        target=target,
        output_dir=output_dir or get_default_output_dir(),
        bom_types=final_types,
        sbom_tool=sbom_tool,
        allow_build_tools=allow_build_tools,
        enrich=enrich,
        live_url=live_url,
        branch=branch,
        token=token,
        provider=provider,
        verbose=verbose,
    )

    # Configure logging
    import logging

    log_level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        datefmt="%H:%M:%S",
    )
    # Suppress noisy third-party loggers even in verbose mode
    for noisy in ("httpx", "httpcore", "urllib3", "openai", "strands", "mcp", "falkordb", "litellm"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    console.print(f"[bold]xBOM v{__version__}[/bold]")
    console.print(f"Target: {target}")
    console.print(f"BOMs: {', '.join(bt.value for bt in final_types)}")
    console.print(f"SBOM tool: {sbom_tool.value}")
    if enrich:
        console.print(f"Enrichment: [green]enabled[/green]")
    console.print(f"Output: {config.output_dir}")

    # Resolve source
    console.print("\n[bold]Resolving source...[/bold]")
    try:
        source_provider = detect_provider(target, provider)
        source_info = source_provider.resolve(target, branch=branch, token=token)
        console.print(f"  Provider: {source_info.provider}")
        console.print(f"  Path: {source_info.local_path}")
        if source_info.commit_sha:
            console.print(f"  Commit: {source_info.commit_sha[:12]}")
    except Exception as e:
        console.print(f"[red]Failed to resolve source: {e}[/red]")
        raise typer.Exit(1)

    # Run scan
    start = time.time()
    try:
        run_scan(source_info, config)
    except Exception as e:
        console.print(f"\n[red]Scan failed: {e}[/red]")
        raise typer.Exit(1)
    finally:
        source_provider.cleanup(source_info)

    elapsed = time.time() - start
    console.print(f"\n[bold green]Scan complete in {elapsed:.1f}s[/bold green]")


@app.command()
def doctor() -> None:
    """Check which external tools and services are installed and running."""
    import socket

    console.print(f"[bold]xBOM v{__version__} — Dependency Check[/bold]\n")

    # ── CLI tools ──────────────────────────────────────────────────────
    tools = [
        ("cdxgen", "SBOM generation (default)", True),
        ("trivy", "SBOM generation (alternative)", False),
        ("semgrep", "CBOM crypto pattern scanning", True),
        ("testssl.sh", "CBOM live TLS scanning", False),
        ("git", "Remote repo cloning", True),
        ("npx", "AI-BOM CodeGraph (MCP server)", False),
        ("node", "Required by cdxgen and npx", False),
    ]

    table = Table(title="CLI Tools", show_header=True)
    table.add_column("Tool", style="bold")
    table.add_column("Status")
    table.add_column("Version")
    table.add_column("Purpose")
    table.add_column("Required")

    all_ok = True
    for name, purpose, required in tools:
        path = find_tool(name)
        if path:
            version = check_tool_version(name) or "unknown"
            status = "[green]installed[/green]"
        else:
            version = "-"
            status = "[red]missing[/red]" if required else "[yellow]missing (optional)[/yellow]"
            if required:
                all_ok = False

        req_str = "Yes" if required else "No"
        table.add_row(name, status, version, purpose, req_str)

    console.print(table)

    # ── Python extras ─────────────────────────────────────────────────
    extras_table = Table(title="\nPython Extras", show_header=True)
    extras_table.add_column("Extra", style="bold")
    extras_table.add_column("Status")
    extras_table.add_column("Package")
    extras_table.add_column("Purpose")

    python_extras = [
        ("agent", "strands", "strands-agents", "AI-BOM LLM enrichment (--enrich)"),
        ("codegraph", "falkordb", "falkordb", "AI-BOM code graph analysis (--enrich)"),
        ("codegraph", "api", "falkordb-code-graph", "AI-BOM code graph indexer (--enrich)"),
        ("apibom", "tree_sitter", "tree-sitter", "API-BOM AST extraction (optional)"),
    ]

    for extra, import_name, package, purpose in python_extras:
        try:
            __import__(import_name)
            extras_table.add_row(extra, "[green]installed[/green]", package, purpose)
        except ImportError:
            extras_table.add_row(extra, "[yellow]not installed[/yellow]", package, purpose)

    console.print(extras_table)

    # ── Services ──────────────────────────────────────────────────────
    svc_table = Table(title="\nServices", show_header=True)
    svc_table.add_column("Service", style="bold")
    svc_table.add_column("Status")
    svc_table.add_column("Address")
    svc_table.add_column("Purpose")

    services = [
        ("FalkorDB", "localhost", 6379, "AI-BOM CodeGraph analysis (--enrich)"),
    ]

    for name, host, port, purpose in services:
        try:
            with socket.create_connection((host, port), timeout=2):
                svc_table.add_row(name, "[green]running[/green]", f"{host}:{port}", purpose)
        except (OSError, ConnectionRefusedError):
            svc_table.add_row(name, "[yellow]not running[/yellow]", f"{host}:{port}", purpose)

    console.print(svc_table)

    # ── Summary ───────────────────────────────────────────────────────
    if all_ok:
        console.print("\n[bold green]All required tools are installed.[/bold green]")
    else:
        console.print("\n[bold red]Some required tools are missing. Install them to use xBOM.[/bold red]")
        raise typer.Exit(1)


@app.command()
def validate(
    file: Annotated[Path, typer.Argument(help="Path to CycloneDX JSON file")],
) -> None:
    """Check that a file is a CycloneDX BOM.

    Checks the format, spec version and serial number, then counts components and services.
    """
    from xbom.utils.cyclonedx import load_bom_json, validate_bom

    if not file.exists():
        console.print(f"[red]File not found: {file}[/red]")
        raise typer.Exit(1)

    try:
        bom = load_bom_json(file)
    except Exception as e:
        console.print(f"[red]Failed to parse JSON: {e}[/red]")
        raise typer.Exit(1)

    issues = validate_bom(bom)
    if issues:
        console.print("[red]Validation issues:[/red]")
        for issue in issues:
            console.print(f"  - {issue}")
        raise typer.Exit(1)

    n_components = len(bom.get("components", []))
    n_services = len(bom.get("services", []))
    spec = bom.get("specVersion", "?")
    console.print(f"[green]Valid CycloneDX {spec} BOM[/green]")
    console.print(f"  Components: {n_components}")
    console.print(f"  Services: {n_services}")


@app.command()
def version() -> None:
    """Show the xBOM version."""
    console.print(f"xbom {__version__}")


if __name__ == "__main__":
    app()
