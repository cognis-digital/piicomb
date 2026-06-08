"""PIICOMB command-line interface.

Subcommands
-----------
scan    Discover PII in a file or directory tree.
redact  Print a copy of a file with every PII span masked.

Examples
--------
    piicomb scan ./customer_exports --format table
    piicomb scan secrets.env --format json --min-score 0.8
    piicomb redact notes.txt
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Optional, Sequence

from . import TOOL_NAME, TOOL_VERSION
from .core import scan_path, scan_file, redact_text


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Local PII discovery for your own files (SSN/CC/passport/DL/email/phone/DOB).",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"{TOOL_NAME} {TOOL_VERSION}",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="discover PII in a path")
    scan.add_argument("path", help="file or directory to scan")
    scan.add_argument(
        "--format",
        choices=("table", "json"),
        default="table",
        help="output format (default: table)",
    )
    scan.add_argument(
        "--min-score",
        type=float,
        default=0.0,
        metavar="F",
        help="only report findings with confidence >= F (0..1)",
    )
    scan.add_argument(
        "--no-recursive",
        action="store_true",
        help="do not descend into subdirectories",
    )
    scan.add_argument(
        "--fail-on-find",
        action="store_true",
        help="exit non-zero when any PII is found (useful in CI)",
    )

    redact = sub.add_parser("redact", help="print a file with PII masked")
    redact.add_argument("path", help="file to redact")
    redact.add_argument(
        "--min-score",
        type=float,
        default=0.0,
        metavar="F",
        help="only mask findings with confidence >= F",
    )
    return parser


def _print_table(result, stream) -> None:
    summary = result.to_dict()["summary"]
    if result.total_findings == 0:
        print("No PII found.", file=stream)
    else:
        for report in result.reports:
            if not report.findings and not report.error:
                continue
            if report.error:
                print(f"\n{report.path}  ({report.error})", file=stream)
                continue
            print(f"\n{report.path}", file=stream)
            print(f"  {'LINE':<6} {'LABEL':<16} {'SCORE':<6} CONTEXT", file=stream)
            for f in report.findings:
                ctx = f.context if len(f.context) <= 60 else f.context[:57] + "..."
                print(f"  {f.line:<6} {f.label:<16} {f.score:<6.2f} {ctx}", file=stream)
    print(
        f"\nScanned {summary['files_scanned']} file(s); "
        f"{summary['files_with_pii']} with PII; "
        f"{summary['total_findings']} finding(s).",
        file=stream,
    )
    if summary["by_label"]:
        breakdown = ", ".join(f"{k}={v}" for k, v in summary["by_label"].items())
        print(f"By type: {breakdown}", file=stream)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if not (0.0 <= args.min_score <= 1.0):
        print("error: --min-score must be between 0.0 and 1.0", file=sys.stderr)
        return 2

    if args.command == "redact":
        report = scan_file(args.path, min_score=args.min_score)
        if report.error:
            print(f"error: {report.error}", file=sys.stderr)
            return 1
        try:
            with open(args.path, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        sys.stdout.write(redact_text(text, min_score=args.min_score))
        if not text.endswith("\n"):
            sys.stdout.write("\n")
        return 0

    # scan
    try:
        result = scan_path(
            args.path,
            recursive=not args.no_recursive,
            min_score=args.min_score,
        )
    except FileNotFoundError:
        print(f"error: no such file or directory: {args.path}", file=sys.stderr)
        return 1

    if args.format == "json":
        json.dump(result.to_dict(), sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        _print_table(result, sys.stdout)

    if args.fail_on_find and result.total_findings > 0:
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
