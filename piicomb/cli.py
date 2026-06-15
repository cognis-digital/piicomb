"""PIICOMB command-line interface.

Subcommands
-----------
scan         Discover PII in a file or directory tree.
redact       Print a copy of a file with every PII span masked.
recognizers  List the bundled recognizers and their base confidences.

Examples
--------
    piicomb scan ./customer_exports --format table
    piicomb scan secrets.env --format json --min-score 0.8 --fail-on-find
    piicomb scan logs/ --only IPV4,EMAIL --no-context
    piicomb redact notes.txt
    piicomb recognizers --format json
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Optional, Sequence

from . import TOOL_NAME, TOOL_VERSION
from .core import (
    RECOGNIZERS,
    scan_path,
    scan_file,
    redact_text,
    recognizer_labels,
)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description=(
            "Local PII discovery for your own files: SSN/ITIN/EIN, credit cards "
            "(Luhn), IBAN (mod-97), passport, driver license, email, phone, "
            "IPv4/IPv6/MAC, DOB, ZIP+4, and high-entropy API secrets, with "
            "context-word confidence boosting."
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"{TOOL_NAME} {TOOL_VERSION}",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    def add_common(p: argparse.ArgumentParser) -> None:
        p.add_argument(
            "--min-score", type=float, default=0.0, metavar="F",
            help="only report findings with confidence >= F (0..1)",
        )
        p.add_argument(
            "--only", default=None, metavar="LABELS",
            help="comma-separated recognizer labels to run (e.g. EMAIL,IPV4)",
        )
        p.add_argument(
            "--no-context", action="store_true",
            help="disable context-word confidence boosting",
        )

    scan = sub.add_parser("scan", help="discover PII in a path")
    scan.add_argument("path", help="file or directory to scan")
    scan.add_argument(
        "--format", choices=("table", "json"), default="table",
        help="output format (default: table)",
    )
    scan.add_argument(
        "--no-recursive", action="store_true",
        help="do not descend into subdirectories",
    )
    scan.add_argument(
        "--fail-on-find", action="store_true",
        help="exit non-zero when any PII is found (useful in CI)",
    )
    add_common(scan)

    redact = sub.add_parser("redact", help="print a file with PII masked")
    redact.add_argument("path", help="file to redact")
    add_common(redact)

    recs = sub.add_parser("recognizers", help="list bundled recognizers")
    recs.add_argument(
        "--format", choices=("table", "json"), default="table",
        help="output format (default: table)",
    )
    return parser


def _parse_only(value: Optional[str]) -> Optional[list[str]]:
    if not value:
        return None
    labels = [s.strip().upper() for s in value.split(",") if s.strip()]
    if not labels:
        raise ValueError("--only value produced no valid labels after parsing; got: " + repr(value))
    valid = set(recognizer_labels())
    bad = [lbl for lbl in labels if lbl not in valid]
    if bad:
        raise ValueError(f"unknown recognizer label(s): {', '.join(bad)}")
    return labels


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
            print(f"  {'LINE':<5} {'LABEL':<15} {'SCORE':<6} {'CTX':<3} CONTEXT", file=stream)
            for f in report.findings:
                ctx = f.context if len(f.context) <= 52 else f.context[:49] + "..."
                boost = "+" if f.context_boosted else " "
                print(f"  {f.line:<5} {f.label:<15} {f.score:<6.2f} {boost:<3} {ctx}", file=stream)
    print(
        f"\nScanned {summary['files_scanned']} file(s); "
        f"{summary['files_with_pii']} with PII; "
        f"{summary['total_findings']} finding(s).",
        file=stream,
    )
    if summary["by_label"]:
        breakdown = ", ".join(f"{k}={v}" for k, v in summary["by_label"].items())
        print(f"By type: {breakdown}", file=stream)


def _cmd_recognizers(fmt: str) -> int:
    rows = [
        {"label": r.label, "base_score": r.score,
         "has_validator": r.validator is not None,
         "context_words": list(r.context)}
        for r in RECOGNIZERS
    ]
    if fmt == "json":
        json.dump({"tool": TOOL_NAME, "version": TOOL_VERSION,
                   "count": len(rows), "recognizers": rows},
                  sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        print(f"{len(rows)} recognizers:\n")
        print(f"  {'LABEL':<15} {'SCORE':<6} {'VALIDATED':<10} CONTEXT WORDS")
        for r in rows:
            ctx = ", ".join(r["context_words"][:5])
            if len(r["context_words"]) > 5:
                ctx += ", …"
            print(f"  {r['label']:<15} {r['base_score']:<6.2f} "
                  f"{('yes' if r['has_validator'] else 'no'):<10} {ctx}")
    return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    try:
        return _main_inner(argv)
    except Exception as exc:  # pragma: no cover
        print(f"error: unexpected failure: {exc}", file=sys.stderr)
        return 2


def _main_inner(argv: Optional[Sequence[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "recognizers":
        return _cmd_recognizers(args.format)

    if not (0.0 <= args.min_score <= 1.0):
        print("error: --min-score must be between 0.0 and 1.0", file=sys.stderr)
        return 2

    try:
        only = _parse_only(args.only)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    use_context = not args.no_context

    if args.command == "redact":
        report = scan_file(args.path, min_score=args.min_score,
                           use_context=use_context, only=only)
        if report.error:
            print(f"error: {report.error}", file=sys.stderr)
            return 1
        try:
            with open(args.path, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        sys.stdout.write(redact_text(text, min_score=args.min_score,
                                     use_context=use_context, only=only))
        if not text.endswith("\n"):
            sys.stdout.write("\n")
        return 0

    # scan
    try:
        result = scan_path(
            args.path,
            recursive=not args.no_recursive,
            min_score=args.min_score,
            use_context=use_context,
            only=only,
        )
    except FileNotFoundError:
        print(f"error: no such file or directory: {args.path}", file=sys.stderr)
        return 1
    except PermissionError as exc:
        print(f"error: permission denied: {exc}", file=sys.stderr)
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
