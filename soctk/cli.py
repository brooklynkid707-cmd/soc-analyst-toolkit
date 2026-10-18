"""Command-line entry point: ``python -m soctk <subcommand>``."""
from __future__ import annotations

import argparse
import sys

from . import __version__, ioc, phish, report, timeline, triage


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="soctk",
        description="SOC Analyst Toolkit - triage, phishing analysis, IOC extraction, timelines and reports.",
    )
    parser.add_argument("--version", action="version", version=f"soctk {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="<command>")
    sub.required = True
    for module in (triage, phish, ioc, timeline, report):
        module.add_parser(sub)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args) or 0)
    except FileNotFoundError as exc:
        print(f"error: file not found: {exc.filename}", file=sys.stderr)
        return 2
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
