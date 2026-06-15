"""PIICOMB engine — recognizers, validation, context-boosting, redaction.

A *recognizer* is a labeled regex paired with an optional checksum/plausibility
validator, a base confidence, and a list of *context words*. When one of those
context words appears near a match (presidio-style "context enhancement"), the
finding's score is boosted; this lets weak patterns (a bare 9-digit number, a
driver-license-shaped token) earn confidence only when the surrounding text
agrees they are PII, while keeping false positives low.

The engine ships with 16 recognizers covering: SSN, ITIN, EIN, credit cards
(Luhn), US passport, driver license, IBAN (mod-97), US/intl phone, email,
IPv4, IPv6, MAC address, dates of birth, US ZIP+4, and high-entropy API
secrets. Findings carry byte offsets, a line number, a masked context snippet,
the matched recognizer, and the (possibly boosted) score so callers can
threshold noise. Redaction masks every accepted span in place.

Standard library only. Zero install. Spirit of microsoft/presidio.
"""

from __future__ import annotations

import datetime
import math
import os
import re
from dataclasses import dataclass, field, asdict
from typing import Callable, Iterable, Iterator, Optional

# ---------------------------------------------------------------------------
# Checksum / plausibility validators
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


def valid_itin(match: str) -> bool:
    """ITIN: 9XX-(70-88|90-92|94-99)-XXXX, formatted like an SSN."""
    digits = re.sub(r"\D", "", match)
    if len(digits) != 9 or digits[0] != "9":
        return False
    group = int(digits[3:5])
    return 70 <= group <= 88 or 90 <= group <= 92 or 94 <= group <= 99


def valid_card(match: str) -> bool:
    digits = re.sub(r"\D", "", match)
    if not (13 <= len(digits) <= 19):
        return False
    return luhn_ok(digits)


def valid_iban(match: str) -> bool:
    """ISO 13616 IBAN validation via the mod-97 check (== 1)."""
    s = re.sub(r"\s", "", match).upper()
    if not (15 <= len(s) <= 34):
        return False
    if not re.match(r"^[A-Z]{2}\d{2}[A-Z0-9]+$", s):
        return False
    rearranged = s[4:] + s[:4]
    digits = "".join(str(int(c, 36)) for c in rearranged)
    # Iterative mod to avoid huge ints (and to be obvious about the algorithm).
    remainder = 0
    for ch in digits:
        remainder = (remainder * 10 + int(ch)) % 97
    return remainder == 1


_DAYS_IN_MONTH = (31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)


def valid_dob(match: str) -> bool:
    """Plausibility check on a date (including day-of-month) so random
    numbers and impossible dates (e.g. 02/30) don't match."""
    parts = [p for p in re.split(r"[/\-.]", match) if p != ""]
    if len(parts) != 3 or not all(p.isdigit() for p in parts):
        return False
    nums = [int(p) for p in parts]
    if len(parts[0]) == 4:
        year, month, day = nums
    else:
        month, day, year = nums
    current_year = datetime.date.today().year
    if not (1900 <= year <= current_year):
        return False
    if not (1 <= month <= 12):
        return False
    return 1 <= day <= _DAYS_IN_MONTH[month - 1]


def valid_ipv4(match: str) -> bool:
    octets = match.split(".")
    if len(octets) != 4:
        return False
    return all(o.isdigit() and 0 <= int(o) <= 255 and (o == "0" or o[0] != "0" or len(o) == 1) for o in octets)


def valid_ipv6(match: str) -> bool:
    s = match.strip()
    if s.count("::") > 1:
        return False
    groups: list[str] = []
    for chunk in s.split("::"):
        groups.extend(g for g in chunk.split(":") if g != "")
    if "::" not in s and len(groups) != 8:
        return False
    if "::" in s and len(groups) > 7:
        return False
    if not groups:
        return False
    return all(len(g) <= 4 and all(c in "0123456789abcdefABCDEF" for c in g) for g in groups)


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for c in s:
        counts[c] = counts.get(c, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def valid_secret(match: str) -> bool:
    """Accept a token as a likely secret only if it is long and high-entropy,
    and mixes character classes — keeps prose words / hex IDs from matching."""
    # Strip an optional ``key=`` / ``: `` prefix the regex captured for context.
    token = re.sub(r"^[\w.\-]+\s*[:=]\s*['\"]?", "", match).strip().strip("'\"")
    if len(token) < 20:
        return False
    has_lower = any(c.islower() for c in token)
    has_upper = any(c.isupper() for c in token)
    has_digit = any(c.isdigit() for c in token)
    classes = sum((has_lower, has_upper, has_digit))
    if classes < 2:
        return False
    return _shannon_entropy(token) >= 3.5


# ---------------------------------------------------------------------------
# Recognizer definition (with context-word boosting)
# ---------------------------------------------------------------------------

# How far (in characters) on either side of a match we look for a context word.
CONTEXT_WINDOW = 40
# Additive boost applied (once) when a context word is present nearby.
CONTEXT_BOOST = 0.30
SCORE_CEILING = 1.0


@dataclass(frozen=True)
class Recognizer:
    label: str
    pattern: "re.Pattern[str]"
    score: float
    validator: Optional[Callable[[str], bool]] = None
    context: tuple[str, ...] = ()

    def matches(self, text: str) -> Iterator[tuple[int, int, str]]:
        for m in self.pattern.finditer(text):
            value = m.group(0)
            if self.validator is None or self.validator(value):
                yield m.start(), m.end(), value


def _rx(pat: str) -> "re.Pattern[str]":
    return re.compile(pat, re.IGNORECASE)


# Pre-compiled context-word matcher per recognizer (built lazily, cached).
_CONTEXT_RX: dict[str, "re.Pattern[str]"] = {}


def _context_present(rec: Recognizer, text: str, start: int, end: int) -> bool:
    if not rec.context:
        return False
    rx = _CONTEXT_RX.get(rec.label)
    if rx is None:
        rx = re.compile(
            r"\b(?:" + "|".join(re.escape(w) for w in rec.context) + r")\b",
            re.IGNORECASE,
        )
        _CONTEXT_RX[rec.label] = rx
    lo = max(0, start - CONTEXT_WINDOW)
    hi = min(len(text), end + CONTEXT_WINDOW)
    window = text[lo:start] + " " + text[end:hi]
    return rx.search(window) is not None


RECOGNIZERS: tuple[Recognizer, ...] = (
    Recognizer(
        "SSN",
        _rx(r"\b\d{3}[- ]\d{2}[- ]\d{4}\b"),
        0.85, valid_ssn,
        ("ssn", "social security", "social", "ss#", "ssn#"),
    ),
    Recognizer(
        "ITIN",
        _rx(r"\b9\d{2}[- ]\d{2}[- ]\d{4}\b"),
        0.6, valid_itin,
        ("itin", "individual taxpayer", "taxpayer id", "tax id"),
    ),
    Recognizer(
        "EIN",
        _rx(r"\b\d{2}-\d{7}\b"),
        0.4,
        None,
        ("ein", "employer identification", "federal tax id", "fein"),
    ),
    Recognizer(
        "CREDIT_CARD",
        _rx(r"\b(?:\d[ -]?){12,18}\d\b"),
        0.9, valid_card,
        ("card", "credit", "visa", "mastercard", "amex", "cc", "ccn", "payment"),
    ),
    Recognizer(
        "IBAN",
        _rx(r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}[ ]?[A-Z0-9]{1,3}\b"),
        0.8, valid_iban,
        ("iban", "account", "bank", "swift", "wire"),
    ),
    Recognizer(
        "EMAIL",
        _rx(r"\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b"),
        0.95,
        None,
        ("email", "e-mail", "contact", "mailto"),
    ),
    Recognizer(
        "PHONE",
        _rx(r"(?<!\d)(?:\+?1[ \-.]?)?(?:\(\d{3}\)|\d{3})[ \-.]\d{3}[ \-.]\d{4}(?!\d)"),
        0.6,
        None,
        ("phone", "tel", "telephone", "mobile", "cell", "call", "fax", "contact"),
    ),
    Recognizer(
        "US_PASSPORT",
        _rx(r"\bpassport\s*(?:no\.?|number|#)?\s*[:#]?\s*([A-Z0-9]\d{8})\b"),
        0.8,
        None,
        ("passport", "travel document"),
    ),
    Recognizer(
        "DRIVER_LICENSE",
        _rx(r"\b(?:driver'?s?\s*licen[cs]e|dl|dln)\s*(?:no\.?|number|#)?\s*[:#]?\s*([A-Z0-9]{6,12})\b"),
        0.5,
        None,
        ("driver", "license", "licence", "dl", "dln", "permit"),
    ),
    Recognizer(
        "DOB",
        _rx(r"\b(?:0?[1-9]|1[0-2])[/\-.](?:0?[1-9]|[12]\d|3[01])[/\-.](?:19|20)\d{2}\b"
            r"|\b(?:19|20)\d{2}[/\-.](?:0?[1-9]|1[0-2])[/\-.](?:0?[1-9]|[12]\d|3[01])\b"),
        0.5, valid_dob,
        ("dob", "date of birth", "born", "birth", "birthdate", "d.o.b"),
    ),
    Recognizer(
        "IPV4",
        _rx(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
        0.5, valid_ipv4,
        ("ip", "address", "host", "client", "remote", "addr", "source", "dest"),
    ),
    Recognizer(
        "IPV6",
        _rx(r"(?<![\w:])(?:[A-F0-9]{1,4}:){2,7}[A-F0-9]{1,4}(?:::)?(?![\w:])"
            r"|(?<![\w:])::(?:[A-F0-9]{1,4}:){0,6}[A-F0-9]{1,4}(?![\w:])"),
        0.55,
        valid_ipv6,
        ("ip", "ipv6", "address", "host", "addr"),
    ),
    Recognizer(
        "MAC_ADDRESS",
        _rx(r"\b(?:[A-F0-9]{2}[:\-]){5}[A-F0-9]{2}\b"),
        0.7,
        None,
        ("mac", "hardware", "ethernet", "nic", "bssid", "hwaddr"),
    ),
    Recognizer(
        "US_ZIP",
        _rx(r"\b\d{5}-\d{4}\b"),
        0.45,
        None,
        ("zip", "postal", "address", "zipcode", "post code"),
    ),
    Recognizer(
        "INTL_PHONE",
        _rx(r"(?<![\d+])\+(?:[1-9]\d{0,2})[ \-.]?(?:\(?\d{1,4}\)?[ \-.]?){2,4}\d{2,4}(?!\d)"),
        0.45,
        None,
        ("phone", "tel", "telephone", "mobile", "cell", "whatsapp", "call"),
    ),
    Recognizer(
        "API_SECRET",
        _rx(r"(?:api[_\-]?key|secret|token|password|passwd|pwd|access[_\-]?key)\s*[:=]\s*"
            r"['\"]?[A-Za-z0-9_\-./+]{20,}['\"]?"),
        0.7, valid_secret,
        ("key", "secret", "token", "password", "credential", "auth", "bearer"),
    ),
)


def recognizer_labels() -> tuple[str, ...]:
    return tuple(r.label for r in RECOGNIZERS)


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
    context_boosted: bool = False

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
            "tool": "piicomb",
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


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------


def _resolve_overlaps(raw: list[Finding]) -> list[Finding]:
    """Keep the highest-scoring finding when spans overlap (longer wins ties).

    Presidio runs an analogous step so a 16-digit credit-card span isn't also
    reported as an IPv4/phone fragment, etc."""
    raw.sort(key=lambda f: (f.start, -(f.end - f.start), -f.score))
    kept: list[Finding] = []
    occupied_end = -1
    for f in raw:
        if f.start >= occupied_end:
            kept.append(f)
            occupied_end = f.end
            continue
        # Overlaps a previously kept span: replace it only if strictly better.
        prev = kept[-1]
        prev_len, cur_len = prev.end - prev.start, f.end - f.start
        better = (f.score, cur_len) > (prev.score, prev_len)
        if better and f.start <= prev.start:
            kept[-1] = f
            occupied_end = f.end
    kept.sort(key=lambda f: (f.start, f.label))
    return kept


def scan_text(
    text: str,
    min_score: float = 0.0,
    use_context: bool = True,
    only: Optional[Iterable[str]] = None,
) -> list[Finding]:
    """Scan a string and return non-overlapping findings sorted by position.

    ``use_context`` enables presidio-style context-word boosting; ``only``
    restricts the active recognizers to the given labels.
    """
    only_set = {s.upper() for s in only} if only else None
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

    raw: list[Finding] = []
    for rec in RECOGNIZERS:
        if only_set is not None and rec.label not in only_set:
            continue
        for start, end, value in rec.matches(text):
            score = rec.score
            boosted = False
            if use_context and _context_present(rec, text, start, end):
                score = min(SCORE_CEILING, score + CONTEXT_BOOST)
                boosted = True
            if score < min_score:
                continue
            raw.append(
                Finding(
                    label=rec.label,
                    value=value.strip(),
                    start=start,
                    end=end,
                    line=line_of(start),
                    score=round(score, 2),
                    context=_snippet(text, start, end),
                    context_boosted=boosted,
                )
            )
    return _resolve_overlaps(raw)


def redact_text(
    text: str,
    min_score: float = 0.0,
    use_context: bool = True,
    only: Optional[Iterable[str]] = None,
) -> str:
    """Return ``text`` with every accepted PII span masked in place."""
    findings = scan_text(text, min_score=min_score, use_context=use_context, only=only)
    if not findings:
        return text
    out: list[str] = []
    cursor = 0
    for f in findings:
        if f.start < cursor:
            continue
        out.append(text[cursor:f.start])
        out.append(_mask(text[f.start:f.end]))
        cursor = f.end
    out.append(text[cursor:])
    return "".join(out)


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


def scan_file(
    path: str,
    min_score: float = 0.0,
    use_context: bool = True,
    only: Optional[Iterable[str]] = None,
) -> FileReport:
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
    report.findings = scan_text(text, min_score=min_score, use_context=use_context, only=only)
    return report


def _iter_files(root: str, recursive: bool) -> Iterator[str]:
    if os.path.isfile(root):
        yield root
        return
    if not recursive:
        try:
            names = sorted(os.listdir(root))
        except PermissionError as exc:
            raise PermissionError(f"cannot list directory: {exc}") from exc
        for name in names:
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
    use_context: bool = True,
    only: Optional[Iterable[str]] = None,
    paths: Optional[Iterable[str]] = None,
) -> ScanResult:
    """Scan a file, a directory, or an explicit iterable of files."""
    result = ScanResult()
    if paths is not None:
        targets: Iterable[str] = paths
    else:
        if not os.path.exists(root):
            raise FileNotFoundError(root)
        targets = _iter_files(root, recursive)
    for path in targets:
        result.reports.append(scan_file(path, min_score=min_score, use_context=use_context, only=only))
    return result
