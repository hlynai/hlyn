# SPDX-License-Identifier: Apache-2.0
"""Laying out a few lines for a person at a terminal: `hlyn claude`'s
before-and-after screens.

Colour only on a terminal, and never with NO_COLOR set (no-color.org); every
line still reads the same without it, since a mark (✓ ✗ !) carries the
meaning, not the colour. Lines are cut to the window, never wrapped: a wrapped
table is the paragraph it was meant to replace.
"""

from __future__ import annotations

import os
import shutil
from typing import TextIO

__all__ = ["Paint", "fit", "squeeze", "table", "width"]

STYLES = {
    "bold": "1", "dim": "2", "green": "32", "red": "31", "yellow": "33", "cyan": "36",
}


class Paint:
    """Colours `text` for `stream`, or leaves it as it is."""

    def __init__(self, stream: TextIO) -> None:
        self.on = (
            hasattr(stream, "isatty") and stream.isatty()
            and not os.environ.get("NO_COLOR") and os.environ.get("TERM") != "dumb"
        )

    def __call__(self, text: str, *styles: str) -> str:
        if not self.on or not styles:
            return text
        codes = ";".join(STYLES[name] for name in styles)
        return f"\x1b[{codes}m{text}\x1b[0m"


def width(stream: TextIO) -> int:
    """The window's width in columns, kept between 60 and 120."""
    try:
        columns = os.get_terminal_size(stream.fileno()).columns
    except (OSError, ValueError, AttributeError):
        columns = 0
    if columns <= 0:  # a terminal that never reported its size says 0
        columns = shutil.get_terminal_size((100, 24)).columns
    return max(60, min(columns, 120))


def squeeze(text: str, room: int) -> str:
    """`text`, cut in the middle to fit `room` columns: both ends of a path
    say more than its middle."""
    if len(text) <= room:
        return text
    if room <= 3:
        return text[:room]
    left = (room - 1) // 2
    return text[:left] + "…" + text[len(text) - (room - 1 - left):]


def fit(items: list[str], room: int, sep: str = ", ") -> str:
    """As many of `items` as fit in `room` columns, then "+N more"."""
    shown: list[str] = []
    for index, item in enumerate(items):
        rest = len(items) - index - 1
        tail = f"  +{rest} more" if rest else ""
        line = sep.join([*shown, item])
        if len(line) + len(tail) > room:
            if not shown:
                left = len(items) - 1
                return squeeze(item, room - (len(f"  +{left} more") if left else 0)) + (
                    f"  +{left} more" if left else "")
            return sep.join(shown) + f"  +{len(items) - len(shown)} more"
        shown.append(item)
    return sep.join(shown)


def table(head: list[str], rows: list[tuple[str, str, list[str | list[str]]]], cols: int, paint: Paint,
          flex: int = 1) -> list[str]:
    """A box-drawn table fitted to `cols`. Each row is (mark, colour, cells);
    the mark is the first column, the cells follow `head`. Column `flex` takes
    what the others leave: a list there ends in "+N more", a path is cut in
    its middle, a sentence at its end. Nothing wraps."""
    def plain(cell: str | list[str]) -> str:
        return ", ".join(cell) if isinstance(cell, list) else cell

    count = len(head)
    wide = [max([len(head[i]), *(len(plain(cells[i])) for _, _, cells in rows)]) for i in range(count)]
    mark_cell = 1
    wide = [w if i == flex else min(w, max(len(head[i]), cols // 3)) for i, w in enumerate(wide)]
    # Indent, borders on both ends and between cells, a space either side of each cell.
    spent = 2 + 1 + count + 1 + sum(w + 2 for w in [mark_cell, *wide]) - wide[flex]
    wide[flex] = max(12, min(wide[flex], cols - spent))

    def line(left: str, mid: str, right: str) -> str:
        pieces = ["─" * (w + 2) for w in [mark_cell, *wide]]
        return "  " + paint(left + mid.join(pieces) + right, "dim")

    def cut(cell: str | list[str], room: int) -> str:
        if isinstance(cell, list):
            return fit(cell, room)
        if cell.startswith(("/", "~", "./")):
            return squeeze(cell, room)
        return cell if len(cell) <= room else cell[: room - 1] + "…"

    bar = paint("│", "dim")
    out = [line("┌", "┬", "┐"),
           "  " + bar + f" {' ':<{mark_cell}} " + bar + bar.join(
               f" {paint(head[i].ljust(wide[i]), 'bold')} " for i in range(count)) + bar,
           line("├", "┼", "┤")]
    for mark, colour, cells in rows:
        shown = [cut(cells[i], wide[i]).ljust(wide[i]) for i in range(count)]
        out.append("  " + bar + f" {paint(mark, colour, 'bold')} " + bar
                   + bar.join(f" {text} " for text in shown) + bar)
    out.append(line("└", "┴", "┘"))
    return out
