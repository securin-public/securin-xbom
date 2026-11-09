"""Tests for the Securin terminal branding."""

from __future__ import annotations

from io import StringIO

import pytest
from rich.console import Console

from xbom.branding import LOGO, LOGOMARK, header, print_launch_screen

VIOLET_ANSI = "\x1b[38;2;156;102;255m"  # BRAND_VIOLET (#9C66FF) as a truecolor escape


def _render(width: int, *, terminal: bool = True, no_color: bool = False) -> str:
    buf = StringIO()
    color_system = "truecolor" if terminal else None
    console = Console(file=buf, width=width, force_terminal=terminal, color_system=color_system, no_color=no_color)
    for renderable in header(console):
        console.print(renderable)
    return buf.getvalue()


@pytest.mark.parametrize("art", [LOGO, LOGOMARK])
def test_art_rows_have_matching_masks(art):
    for chars, mask in art:
        assert len(chars) == len(mask)
        assert set(mask) <= {"v", "w", " "}
        # A cell is empty exactly when its mask says so
        assert all((ch == " ") == (kind == " ") for ch, kind in zip(chars, mask, strict=True))


def test_wide_terminal_gets_full_logo_in_brand_violet():
    out = _render(100)
    assert VIOLET_ANSI in out
    assert "▄▄▄▄▄▄" in out  # wordmark row
    assert "xBOM" in out and "by Securin" in out


def test_narrow_terminal_gets_logomark_beside_title():
    out = _render(60)
    assert VIOLET_ANSI in out
    assert "▄▄▄▄▄▄   ▄▄▄▄▄▄" not in out  # no wordmark
    assert "by Securin" in out


def test_piped_output_is_plain_text():
    out = _render(100, terminal=False)
    assert not set(out) & set("▀▄█")
    assert "\x1b[" not in out
    assert "xBOM v" in out


def test_no_color_drops_logo_and_colors():
    out = _render(100, no_color=True)
    assert not set(out) & set("▀▄█")
    assert "\x1b[38;" not in out  # NO_COLOR still allows bold/dim, but no colors
    assert "xBOM" in out


def test_launch_screen_lists_quick_start_and_commands():
    buf = StringIO()
    print_launch_screen(Console(file=buf, width=100), [("scan", "Scan a project"), ("doctor", "Check tools")])
    out = buf.getvalue()
    assert "Quick start" in out and "xbom scan ." in out
    assert "Commands" in out and "Scan a project" in out and "Check tools" in out
    assert "xbom <command> --help" in out
