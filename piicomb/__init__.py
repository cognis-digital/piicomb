"""PIICOMB — local PII discovery for your own files.

Scans text-bearing files on disk for personally identifiable information
(SSN, credit cards, passports, driver licenses, emails, phones, dates of
birth) using regex recognizers plus context-aware validation (Luhn for
cards, area/group checks for SSNs). Standard library only, zero install.

Spirit of microsoft/presidio, shrunk to a single dependency-free package.
"""

from .core import (
    Finding,
    FileReport,
    ScanResult,
    RECOGNIZERS,
    scan_text,
    scan_file,
    scan_path,
    redact_text,
)

TOOL_NAME = "piicomb"
TOOL_VERSION = "1.0.0"

__all__ = [
    "TOOL_NAME",
    "TOOL_VERSION",
    "Finding",
    "FileReport",
    "ScanResult",
    "RECOGNIZERS",
    "scan_text",
    "scan_file",
    "scan_path",
    "redact_text",
]
