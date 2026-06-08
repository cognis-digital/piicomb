"""PIICOMB engine — recognizers, validation, scanning, redaction.

A "recognizer" is a labeled regex with an optional validator and a
confidence score. Validators reject false positives (e.g. a 16-digit
number that fails the Luhn checksum is not flagged as a credit card).
Findings carry byte offsets, a one-line redacted context snippet, and a
score so callers can threshold noise.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field, asdict
from typing import Callable, Iterable, Iterator, Optional

# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------


def luhn_ok(digits: str) -> bool:
    """Validate a numeric string with the Luhn (mod-10) checksum."""
    nums = [int(c) for c in digits if c.isdigit()]
    if len(nums) < 12:
        return False
    total = 0
    parity = len(nums) % 2
    for i, n in enumerate(nums):
        if i % 2 == parity:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def valid_ssn(match: str) -> bool:
    """Reject SSNs that the SSA never issues."""
    digits = re.sub(r"\D", "", match)
    if len(digits) != 9:
        return False
    area, group, serial = digits[:3], digits[3:5], digits[5:]
    if area in ("000", "666") or area[0] == "9":
        return False
    if group == "00" or serial == "0000":
        return False
    if digits == digits[0] * 9:  # 000000000, 111111111, ...
        return False
    return True


def valid_card(match: str) -> bool:
    digits = re.sub(r"\D", "", match)
    if not (13 <= len(digits) <= 19):
        return False
    return luhn_ok(digits)


_DAYS_IN_MONTH = (31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)


def valid_dob(match: str) -> bool:
    """A plausibility check on a date (incl. day-of-month) so random
    numbers and impossible dates (e.g. 02/30) don't match."""
    parts = [p for p in re.split(r"[/\-.]", match) if p != ""]
    if len(parts) != 3:
        return False
    if not all(p.isdigit() for p in parts):
        return False
    nums = [int(p) for p in parts]
    # Year is the 4-digit component; the others are month/day in order.
    if len(parts[0]) == 4:
        year, month, day = nums[0], nums[1], nums[2]
    else:
        month, day, year = nums[0], nums[1], nums[2]
    if not (1900 <= year <= 2025):
        return False
    if not (1 <= month <= 12):
        return False
    if not (1 <= day <= _DAYS_IN_MONTH[month - 1]):
        return False
    return True


# ---------------------------------------------------------------------------
# Recognizer definition
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Recognizer:
    label: str
    pattern: "re.Pattern[str]"
    score: float
    validator: Optional[Callable[[str], bool]] = None

    def matches(self, text: str) -> Iterator[tuple[int, int, str]]:
        for m in self.pattern.finditer(text):
            value = m.group(0)
            if self.validator is None or self.validator(value):
                yield m.start(), m.end(), value


def _rx(pat: str) -> "re.Pattern[str]":
    return re.compile(pat, re.IGNORECASE)


RECOGNIZERS: tuple[Recognizer, ...] = (
    Recognizer(
        "SSN",
        _rx(r"\b\d{3}[- ]\d{2}[- ]\d{4}\b"),
        0.85,
        valid_ssn,
    ),
    Recognizer(
        "CREDIT_CARD",
        _rx(r"\b(?:\d[ -]?){12,18}\d\b"),
        0.9,
        valid_card,
    ),
    Recognizer(
        "EMAIL",
        _rx(r"\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b"),
        0.95,
    ),
    Recognizer(
        "PHONE",
        _rx(r"(?<!\d)(?:\+?1[ \-.]?)?(?:\(\d{3}\)|\d{3})[ \-.]\d{3}[ \-.]\d{4}(?!\d)"),
        0.7,
    ),
    Recognizer(
        # US passport: one letter or digit followed by 8 digits, or 9 digits.
        "US_PASSPORT",
        _rx(r"\bpassport\s*(?:no\.?|number|#)?\s*[:#]?\s*([A-Z0-9]\d{8})\b"),
        0.8,
    ),
    Recognizer(
        "DRIVER_LICENSE",
        _rx(r"\b(?:driver'?s?\s*licen[cs]e|dl|dln)\s*(?:no\.?|number|#)?\s*[:#]?\s*([A-Z0-9]{6,12})\b"),
        0.6,
    ),
    Recognizer(
        "DOB",
        _rx(r"\b(?:0?[1-9]|1[0-2])[/\-.](?:0?[1-9]|[12]\d|3[01])[/\-.](?:19|20)\d{2}\b"
            r"|\b(?:19|20)\d{2}[/\-.](?:0?[1-9]|1[0-2])[/\-.](?:0?[1-9]|[12]\d|3[01])\b"),
        0.5,
        valid_dob,
    ),
)


# ---------------------------------------------------------------------------
# Findings & reports
# ---------------------------------------------------------------------------


@dataclass
class Finding:
    label: str
    value: str
    start: int
    end: int
    line: int
    score: float
    context: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class FileReport:
    path: str
    findings: list[Finding] = field(default_factory=list)
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "error": self.error,
            "findings": [f.to_dict() for f in self.findings],
        }


@dataclass
class ScanResult:
    reports: list[FileReport] = field(default_factory=list)

    @property
    def total_findings(self) -> int:
        return sum(len(r.findings) for r in self.reports)

    @property
    def files_with_pii(self) -> int:
        return sum(1 for r in self.reports if r.findings)

    def label_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for r in self.reports:
            for f in r.findings:
                counts[f.label] = counts.get(f.label, 0) + 1
        return dict(sorted(counts.items()))

    def to_dict(self) -> dict:
        return {
            "summary": {
                "files_scanned": len(self.reports),
                "files_with_pii": self.files_with_pii,
                "total_findings": self.total_findings,
                "by_label": self.label_counts(),
            },
            "reports": [r.to_dict() for r in self.reports if r.findings or r.error],
        }


# ---------------------------------------------------------------------------
# Redaction helpers
# ---------------------------------------------------------------------------


def _mask(value: str) -> str:
    """Mask a value keeping its last 4 significant characters."""
    keep = "".join(c for c in value if c.isalnum())[-4:]
    return f"[REDACTED-…{keep}]" if keep else "[REDACTED]"


def _snippet(text: str, start: int, end: int, width: int = 24) -> str:
    lo = max(0, start - width)
    hi = min(len(text), end + width)
    before = text[lo:start].replace("\n", " ")
    after = text[end:hi].replace("\n", " ")
    return f"{'…' if lo else ''}{before}{_mask(text[start:end])}{after}{'…' if hi < len(text) else ''}"


def redact_text(text: str, min_score: float = 0.0) -> str:
    """Return ``text`` with every recognized PII span masked in place."""
    spans: list[tuple[int, int]] = []
    for rec in RECOGNIZERS:
        if rec.score < min_score:
            continue
        for start, end, _ in rec.matches(text):
            spans.append((start, end))
    if not spans:
        return text
    spans.sort()
    out: list[str] = []
    cursor = 0
    last_end = -1
    for start, end in spans:
        if start < last_end:  # skip overlaps already covered
            continue
        out.append(text[cursor:start])
        out.append(_mask(text[start:end]))
        cursor = end
        last_end = end
    out.append(text[cursor:])
    return "".join(out)


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------


def scan_text(text: str, min_score: float = 0.0) -> list[Finding]:
    """Scan a string and return findings sorted by position."""
    findings: list[Finding] = []
    line_starts = [0]
    for i, ch in enumerate(text):
        if ch == "\n":
            line_starts.append(i + 1)

    def line_of(pos: int) -> int:
        lo, hi = 0, len(line_starts) - 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if line_starts[mid] <= pos:
                lo = mid
            else:
                hi = mid - 1
        return lo + 1

    for rec in RECOGNIZERS:
        if rec.score < min_score:
            continue
        for start, end, value in rec.matches(text):
            findings.append(
                Finding(
                    label=rec.label,
                    value=value.strip(),
                    start=start,
                    end=end,
                    line=line_of(start),
                    score=rec.score,
                    context=_snippet(text, start, end),
                )
            )
    findings.sort(key=lambda f: (f.start, f.label))
    return findings


_BINARY_HINT = b"\x00"
_TEXT_EXTS = {
    ".txt", ".csv", ".tsv", ".log", ".md", ".json", ".yaml", ".yml",
    ".ini", ".cfg", ".conf", ".html", ".htm", ".xml", ".sql", ".env",
    ".py", ".js", ".ts", ".java", ".rb", ".go", ".sh", ".tex", "",
}
_MAX_BYTES = 5_000_000


def _looks_textual(path: str) -> bool:
    ext = os.path.splitext(path)[1].lower()
    if ext in _TEXT_EXTS:
        return True
    try:
        with open(path, "rb") as fh:
            chunk = fh.read(2048)
    except OSError:
        return False
    return _BINARY_HINT not in chunk


def scan_file(path: str, min_score: float = 0.0) -> FileReport:
    report = FileReport(path=path)
    try:
        size = os.path.getsize(path)
        if size > _MAX_BYTES:
            report.error = f"skipped: file too large ({size} bytes)"
            return report
        if not _looks_textual(path):
            report.error = "skipped: binary file"
            return report
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError as exc:
        report.error = f"read error: {exc}"
        return report
    report.findings = scan_text(text, min_score=min_score)
    return report


def _iter_files(root: str, recursive: bool) -> Iterator[str]:
    if os.path.isfile(root):
        yield root
        return
    if not recursive:
        for name in sorted(os.listdir(root)):
            full = os.path.join(root, name)
            if os.path.isfile(full):
                yield full
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in sorted(dirnames) if not d.startswith(".")]
        for name in sorted(filenames):
            yield os.path.join(dirpath, name)


def scan_path(
    root: str,
    recursive: bool = True,
    min_score: float = 0.0,
    paths: Optional[Iterable[str]] = None,
) -> ScanResult:
    """Scan a file, a directory, or an explicit iterable of files."""
    result = ScanResult()
    targets: Iterable[str]
    if paths is not None:
        targets = paths
    else:
        if not os.path.exists(root):
            raise FileNotFoundError(root)
        targets = _iter_files(root, recursive)
    for path in targets:
        result.reports.append(scan_file(path, min_score=min_score))
    return result
