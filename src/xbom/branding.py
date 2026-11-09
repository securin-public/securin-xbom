"""Securin branding for the terminal: logo art and the launch screen shown by bare `xbom`."""

from __future__ import annotations

from rich.console import Console, Group, RenderableType
from rich.table import Table
from rich.text import Text

from xbom import __version__

BRAND_VIOLET = "#9C66FF"
REPO_URL = "https://github.com/securin-public/securin-xbom"

TAGLINE = "Generate SBOM, AI-BOM, CBOM and API-BOM for a codebase, merged into one CycloneDX 1.6 file."

QUICK_START = [
    ("xbom scan .", "Scan the current project"),
    ("xbom scan https://github.com/org/repo", "Scan a remote repository"),
    ("xbom doctor", "Check which tools are installed"),
]

# The Securin logo in half-block characters (two pixels per cell), rendered from the brand
# logo PNGs. Each row is (chars, mask): in the mask, "v" is the violet mark and "w" the
# wordmark, which keeps the terminal's own text color so it reads on light and dark themes.
LOGO: list[tuple[str, str]] = [
    ("     ▄▄██▄▄    ▄▄▄▄▄▄   ▄▄▄▄▄▄    ▄▄▄▄▄▄   ▄     ▄  ▄▄ ▄▄▄  ▄▄  ▄▄▄▄▄▄▄ ",
     "     vvvvvv    wwwwww   wwwwww    wwwwww   w     w  ww www  ww  wwwwwww "),
    ("  ▄██ ▀▀▀▀    ██▀▀▀▀▀  ██▀▀▀▀██  ██▀▀▀▀▀  ██     █  ██▀▀▀██ ██  ██▀▀▀▀██",
     "  vvv vvvv    wwwwwww  wwwwwwww  wwwwwww  ww     w  wwwwwww ww  wwwwwwww"),
    ("  ███   ▄▄    ▀█▄▄▄▄▄  ██▄▄▄▄██  ██       ██     █  ██    ▀ ██  ██    ██",
     "  vvv   vv    wwwwwww  wwwwwwww  ww       ww     w  ww    w ww  ww    ww"),
    ("  ▀▀   ███     ▀▀▀▀▀██ ██▀▀▀▀▀▀  ██       ██     █  ██      ██  ██    ██",
     "  vv   vvv     wwwwwww wwwwwwww  ww       ww     w  ww      ww  ww    ww"),
    (" ▄▄▄▄  ██▀    ▄▄▄▄▄▄██ ▀█▄▄▄▄▄▄  ██▄▄▄▄▄  ▀█▄▄▄▄▄█  ██      ██  ██    ██",
     " vvvv  vvv    wwwwwwww wwwwwwww  wwwwwww  wwwwwwww  ww      ww  ww    ww"),
    ("▀▀███▀▀        ▀▀▀▀▀▀   ▀▀▀▀▀▀▀   ▀▀▀▀▀▀   ▀▀▀▀▀ ▀  ▀▀      ▀▀  ▀▀    ▀▀",
     "vvvvvvv        wwwwww   wwwwwww   wwwwww   wwwww w  ww      ww  ww    ww"),
]

# Just the mark, shown beside the title when the terminal is too narrow for LOGO
LOGOMARK: list[tuple[str, str]] = [
    ("      ▄▄███▄▄",
     "      vvvvvvv"),
    ("  ▄▄██▀▀▀██▀▀",
     "  vvvvvvvvvvv"),
    ("  ████     ▄ ",
     "  vvvv     v "),
    ("  ███▀  ▄███ ",
     "  vvvv  vvvv "),
    ("  ▀     ████ ",
     "  v     vvvv "),
    (" ▄▄██▄▄▄██▀▀ ",
     " vvvvvvvvvvv "),
    (" ▀▀███▀▀     ",
     " vvvvvvv     "),
]

_FULL_LOGO_WIDTH = max(len(chars) for chars, _ in LOGO)


def header(console: Console) -> list[RenderableType]:
    """Logo plus product line, sized to the terminal.

    The logo is only drawn on a color terminal; piped output and NO_COLOR get plain text.
    """
    title = Text.assemble(("xBOM", "bold"), (f" v{__version__}", "dim"), ("  ·  by Securin", "dim"))

    if not _can_draw_art(console):
        return [title, Text(TAGLINE)]

    if console.width >= _FULL_LOGO_WIDTH + 2:
        return [*_art(LOGO), Text(), title, Text(TAGLINE)]

    # Narrow terminal: small mark on the left, title and tagline beside it
    side = Text("\n").join([Text(), title, Text(TAGLINE)])
    grid = Table.grid(padding=(0, 2))
    grid.add_column(no_wrap=True)
    grid.add_column(vertical="middle")
    grid.add_row(Text("\n").join(_art(LOGOMARK)), side)
    return [grid]


def print_launch_screen(console: Console, commands: list[tuple[str, str]]) -> None:
    """Print what bare `xbom` shows: logo, what the tool is, a quick start and the commands."""
    for renderable in header(console):
        console.print(renderable)

    console.print()
    console.print(section("Quick start", QUICK_START))
    console.print()
    console.print(section("Commands", commands))
    console.print()
    console.print(Text(f"Run 'xbom <command> --help' for options · {REPO_URL}", style="dim"))


def section(title: str, rows: list[tuple[str, str]]) -> Group:
    """A violet heading over an indented two-column list (command, description)."""
    return Group(Text(title, style=f"bold {BRAND_VIOLET}"), _two_columns(rows))


def _can_draw_art(console: Console) -> bool:
    return console.is_terminal and console.color_system is not None and not console.no_color


def _art(rows: list[tuple[str, str]]) -> list[Text]:
    lines = []
    for chars, mask in rows:
        line = Text(no_wrap=True)
        for ch, kind in zip(chars, mask, strict=True):
            line.append(ch, style=BRAND_VIOLET if kind == "v" else "")
        lines.append(line)
    return lines


def _two_columns(rows: list[tuple[str, str]]) -> Table:
    grid = Table.grid(padding=(0, 3))
    grid.add_column(style="bold", no_wrap=True)
    grid.add_column(style="dim")
    for left, right in rows:
        grid.add_row(Text("  " + left), Text(right))
    return grid
