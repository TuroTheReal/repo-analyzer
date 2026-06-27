"""Reporters: render a :class:`~repo_analyzer.report.Report` into each format.

Every reporter exposes ``render(report) -> str``. The CLI picks which ones to
run from the configured output formats.
"""

from ..report import Report
from . import html, json_report, markdown, sarif

# Maps a format name (as used in config / CLI) to its renderer and file name.
REPORTERS: dict[str, tuple] = {
    "sarif": (sarif.render, "report.sarif"),
    "markdown": (markdown.render, "report.md"),
    "html": (html.render, "report.html"),
    "json": (json_report.render, "report.json"),
}

__all__ = ["Report", "REPORTERS"]
