"""PIICOMB — local PII discovery and redaction for your own files.

Scans text-bearing files on disk for personally identifiable information
using 16 regex recognizers plus checksum/plausibility validation (Luhn for
cards, mod-97 for IBAN, area/group rules for SSN, calendar checks for DOB,
Shannon-entropy for secrets) and presidio-style context-word confidence
boosting. Overlapping spans are resolved to the strongest finding, and any
accepted span can be masked in place.

Recognizers: SSN, ITIN, EIN, CREDIT_CARD, IBAN, EMAIL, PHONE, INTL_PHONE,
US_PASSPORT, DRIVER_LICENSE, DOB, IPV4, IPV6, MAC_ADDRESS, US_ZIP, API_SECRET.

Standard library only, zero install. Spirit of microsoft/presidio, shrunk to
a single dependency-free package.
"""

from .core import (
    Finding,
    FileReport,
    ScanResult,
    Recognizer,
    RECOGNIZERS,
    recognizer_labels,
    scan_text,
    scan_file,
    scan_path,
    redact_text,
    luhn_ok,
    valid_ssn,
    valid_itin,
    valid_card,
    valid_iban,
    valid_dob,
    valid_ipv4,
    valid_ipv6,
    valid_secret,
)

TOOL_NAME = "piicomb"
TOOL_VERSION = "2.0.0"

__all__ = [
    "TOOL_NAME",
    "TOOL_VERSION",
    "Finding",
    "FileReport",
    "ScanResult",
    "Recognizer",
    "RECOGNIZERS",
    "recognizer_labels",
    "scan_text",
    "scan_file",
    "scan_path",
    "redact_text",
    "luhn_ok",
    "valid_ssn",
    "valid_itin",
    "valid_card",
    "valid_iban",
    "valid_dob",
    "valid_ipv4",
    "valid_ipv6",
    "valid_secret",
]
