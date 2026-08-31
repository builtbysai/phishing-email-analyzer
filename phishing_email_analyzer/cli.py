"""Command-line interface for local batch analysis."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Sequence

from .analyzer import analyze_path
from .reporting import write_html_report, write_json_report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="phishing-email-analyzer",
        description="Analyze raw .eml files for structural phishing indicators without network access.",
    )
    parser.add_argument("input", help="One .eml file or a directory containing .eml files")
    parser.add_argument("--html", default="phishing-report.html", help="HTML output path (default: phishing-report.html)")
    parser.add_argument("--json", default="phishing-report.json", help="JSON output path (default: phishing-report.json)")
    parser.add_argument("--recursive", action="store_true", help="Search input directories recursively")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        analyses = analyze_path(args.input, recursive=args.recursive)
    except (FileNotFoundError, ValueError, OSError) as exc:
        parser.error(str(exc))

    html_path = write_html_report(analyses, Path(args.html))
    json_path = write_json_report(analyses, Path(args.json))
    flagged = sum(item.risk_level in {"high", "critical"} for item in analyses)
    print(f"Analyzed {len(analyses)} email(s); {flagged} high/critical risk.")
    print(f"HTML report: {html_path.resolve()}")
    print(f"JSON export: {json_path.resolve()}")
    return 0
