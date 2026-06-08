"""PIICOMB — Local PII discovery in your own files (SSN/CC/passport/DL/email/phone/DOB)."""
from __future__ import annotations
import re, time
from pathlib import Path
from cognis_core import Finding, ScanResult, score

TOOL_NAME = "PIICOMB"
TOOL_VERSION = "0.1.0"

# Conservative patterns. Production should layer Microsoft Presidio for NER.
PII = [
    ("PII-SSN-001", "critical", 3.0, "US_SSN",
     r"\b\d{3}-\d{2}-\d{4}\b",
     "Encrypt at rest, restrict access, and run PIICOMB pre-commit."),
    ("PII-CC-001", "critical", 3.0, "CREDIT_CARD",
     r"\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6011)[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b",
     "PCI DSS scope. Tokenize and remove from non-PCI systems."),
    ("PII-EMAIL-001", "low", 1.0, "EMAIL",
     r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
     "Consider whether email exposure is intended."),
    ("PII-PHONE-001", "low", 1.2, "PHONE_US",
     r"(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
     "Mask or redact unless explicitly needed."),
    ("PII-DOB-001", "medium", 2.0, "DOB",
     r"\b(?:0[1-9]|1[012])[/-](?:0[1-9]|[12][0-9]|3[01])[/-](?:19|20)\d{2}\b",
     "DOB combined with name = PII under most privacy laws."),
    ("PII-PASS-001", "high", 2.5, "US_PASSPORT",
     r"\b[A-Z]\d{8}\b",
     "Looks like a US passport number. Verify and protect."),
    ("PII-DL-001", "high", 2.5, "US_DL",
     r"\b[A-Z]\d{7,8}\b",
     "Looks like a driver's license. Verify and protect."),
]


def scan(target: str, **opts) -> ScanResult:
    t0 = time.time()
    result = ScanResult(tool_name=TOOL_NAME, tool_version=TOOL_VERSION, target=str(target))
    p = Path(target)
    exts = (".txt", ".md", ".csv", ".json", ".log", ".yaml", ".yml",
            ".sql", ".py", ".ini", ".cfg", ".env", ".html", ".tsv")
    if p.is_file():
        files: list[Path] = [p]
    elif p.is_dir():
        files = [f for f in p.rglob("*")
                 if f.is_file() and (f.suffix.lower() in exts or f.suffix == "")]
    else:
        files = []

    result.items_scanned = len(files)
    for f in files:
        try:
            text = f.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        seen_in_file: dict[str, int] = {}
        for rid, sev, w, cat, pat, rem in PII:
            for m in re.finditer(pat, text):
                line = text.count("\n", 0, m.start()) + 1
                # Avoid PASS/DL double-matching (passport is also valid DL-ish)
                key = f"{cat}:{m.start()}"
                if key in seen_in_file:
                    continue
                seen_in_file[key] = 1
                result.add(Finding(
                    id=rid, severity=sev, weight=w, title=cat,
                    description=f"{cat} match: `{m.group(0)[:30]}...`",
                    location=f"{f}:{line}", remediation=rem, category="pii",
                ))
    result.composite_score, result.risk_level = score(result.findings)
    result.scan_duration_ms = int((time.time() - t0) * 1000)
    return result
