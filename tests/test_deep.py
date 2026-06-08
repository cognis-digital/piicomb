"""Deep tests for PIICOMB 2.x — the expanded recognizer set, checksum
validators, context-word boosting, overlap resolution, redaction, and the new
CLI subcommands. Standard library only, no network."""

import io
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from piicomb import TOOL_NAME, TOOL_VERSION  # noqa: E402
from piicomb import (  # noqa: E402
    scan_text,
    redact_text,
    recognizer_labels,
    RECOGNIZERS,
    luhn_ok,
    valid_iban,
    valid_itin,
    valid_ipv4,
    valid_ipv6,
    valid_secret,
)
from piicomb.core import scan_path  # noqa: E402
from piicomb import cli  # noqa: E402

DEEP_LOG = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "demos", "02-deep", "incident_dump.log",
)


class TestVersionBumped(unittest.TestCase):
    def test_v2(self):
        self.assertEqual(TOOL_NAME, "piicomb")
        self.assertTrue(TOOL_VERSION.startswith("2."), TOOL_VERSION)


class TestRecognizerCoverage(unittest.TestCase):
    def test_at_least_15_types(self):
        self.assertGreaterEqual(len(recognizer_labels()), 15)

    def test_expected_labels_present(self):
        labels = set(recognizer_labels())
        for expected in (
            "SSN", "ITIN", "EIN", "CREDIT_CARD", "IBAN", "EMAIL", "PHONE",
            "INTL_PHONE", "US_PASSPORT", "DRIVER_LICENSE", "DOB", "IPV4",
            "IPV6", "MAC_ADDRESS", "US_ZIP", "API_SECRET",
        ):
            self.assertIn(expected, labels, f"missing {expected}")

    def test_labels_unique(self):
        labels = recognizer_labels()
        self.assertEqual(len(labels), len(set(labels)))

    def test_every_recognizer_compiles(self):
        # Each recognizer must run against a benign string without raising.
        for rec in RECOGNIZERS:
            list(rec.matches("nothing to see here 12345"))


class TestNewValidators(unittest.TestCase):
    def test_iban_mod97(self):
        self.assertTrue(valid_iban("GB82 WEST 1234 5698 7654 32"))
        self.assertTrue(valid_iban("DE89370400440532013000"))
        self.assertFalse(valid_iban("GB82 WEST 1234 5698 7654 33"))  # bad check

    def test_itin(self):
        self.assertTrue(valid_itin("912-78-3456"))    # 9xx + group 78
        self.assertFalse(valid_itin("912-50-3456"))   # group out of range
        self.assertFalse(valid_itin("536-42-7188"))   # not 9xx

    def test_ipv4(self):
        self.assertTrue(valid_ipv4("203.0.113.47"))
        self.assertFalse(valid_ipv4("999.1.2.3"))     # octet > 255
        self.assertFalse(valid_ipv4("10.0.0"))        # too few octets

    def test_ipv6(self):
        self.assertTrue(valid_ipv6("2001:0db8:85a3:0000:0000:8a2e:0370:7334"))
        self.assertTrue(valid_ipv6("fe80::1"))
        self.assertFalse(valid_ipv6("2001::85a3::7334"))  # two ::

    def test_secret_entropy(self):
        self.assertTrue(valid_secret("api_key=sk_live_EXAMPLE_9aZ2bX7qK"))
        self.assertFalse(valid_secret("password=password"))         # low entropy
        self.assertFalse(valid_secret("token=aaaaaaaaaaaaaaaaaaaa"))  # one class


class TestContextBoosting(unittest.TestCase):
    def test_ssn_context_raises_score(self):
        plain = scan_text("value 536-42-7188 logged", use_context=False)
        with_ctx = scan_text("SSN: 536-42-7188 logged", use_context=True)
        ssn_plain = next(f for f in plain if f.label == "SSN")
        ssn_ctx = next(f for f in with_ctx if f.label == "SSN")
        self.assertGreater(ssn_ctx.score, ssn_plain.score)
        self.assertTrue(ssn_ctx.context_boosted)
        self.assertFalse(ssn_plain.context_boosted)

    def test_min_score_uses_boosted_value(self):
        # IPV4 base is 0.5; with the "client" context word it clears 0.7.
        text = "client 203.0.113.47 connected"
        hits = scan_text(text, min_score=0.7, use_context=True)
        self.assertTrue(any(f.label == "IPV4" for f in hits))
        # Without context it should be filtered out at the same threshold.
        none = scan_text("203.0.113.47", min_score=0.7, use_context=True)
        self.assertFalse(any(f.label == "IPV4" for f in none))


class TestOverlapResolution(unittest.TestCase):
    def test_card_not_double_reported(self):
        # A 16-digit card could also look like IPv4-ish/phone fragments; only
        # one non-overlapping finding should survive over that span.
        text = "card 4111 1111 1111 1111 end"
        findings = scan_text(text)
        spans = [(f.start, f.end) for f in findings]
        for i in range(len(spans)):
            for j in range(i + 1, len(spans)):
                a, b = spans[i], spans[j]
                self.assertFalse(a[0] < b[1] and b[0] < a[1],
                                 f"overlap {a} {b}")
        self.assertTrue(any(f.label == "CREDIT_CARD" for f in findings))


class TestDecoysRejected(unittest.TestCase):
    def test_decoys(self):
        text = ("ip 999.1.2.3 card 1234 5678 9012 3456 "
                "ssn 000-12-3456 dob 02/30/1991")
        labels = {f.label for f in scan_text(text)}
        self.assertNotIn("CREDIT_CARD", labels)
        self.assertNotIn("SSN", labels)
        self.assertNotIn("DOB", labels)
        self.assertNotIn("IPV4", labels)


class TestDeepDemoFile(unittest.TestCase):
    def setUp(self):
        self.result = scan_path(DEEP_LOG)
        self.counts = self.result.label_counts()

    def test_many_types_detected(self):
        # The log is engineered to exercise the breadth of the recognizer set.
        self.assertGreaterEqual(len(self.counts), 10, self.counts)

    def test_specific_types(self):
        for expected in ("EMAIL", "CREDIT_CARD", "IBAN", "SSN", "IPV4",
                         "IPV6", "MAC_ADDRESS", "US_PASSPORT", "API_SECRET"):
            self.assertIn(expected, self.counts, f"missing {expected}")

    def test_decoy_serials_not_flagged_as_cards(self):
        # The Luhn-invalid 1234... must not appear as a credit card.
        for r in self.result.reports:
            for f in r.findings:
                if f.label == "CREDIT_CARD":
                    self.assertTrue(luhn_ok(f.value))


class TestRedaction(unittest.TestCase):
    def test_removes_sensitive_values(self):
        text = "SSN 536-42-7188 card 4111 1111 1111 1111 mail a@b.com"
        out = redact_text(text)
        self.assertNotIn("536-42-7188", out)
        self.assertNotIn("4111 1111 1111 1111", out)
        self.assertNotIn("a@b.com", out)
        self.assertIn("[REDACTED", out)

    def test_redact_preserves_clean_text(self):
        self.assertEqual(redact_text("just a sentence"), "just a sentence")


class TestCLI(unittest.TestCase):
    def _capture(self, argv):
        out, err = io.StringIO(), io.StringIO()
        old_out, old_err = sys.stdout, sys.stderr
        sys.stdout, sys.stderr = out, err
        try:
            code = cli.main(argv)
        finally:
            sys.stdout, sys.stderr = old_out, old_err
        return code, out.getvalue(), err.getvalue()

    def test_scan_json_breakdown(self):
        code, out, _ = self._capture(["scan", DEEP_LOG, "--format", "json"])
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertEqual(data["tool"], "piicomb")
        self.assertGreaterEqual(len(data["summary"]["by_label"]), 10)

    def test_fail_on_find_nonzero(self):
        code, _, _ = self._capture(["scan", DEEP_LOG, "--fail-on-find"])
        self.assertEqual(code, 1)

    def test_only_filter(self):
        code, out, _ = self._capture(
            ["scan", DEEP_LOG, "--only", "EMAIL", "--format", "json"])
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertEqual(set(data["summary"]["by_label"]), {"EMAIL"})

    def test_only_rejects_unknown_label(self):
        code, _, err = self._capture(["scan", DEEP_LOG, "--only", "BOGUS"])
        self.assertEqual(code, 2)
        self.assertIn("unknown recognizer", err)

    def test_recognizers_json(self):
        code, out, _ = self._capture(["recognizers", "--format", "json"])
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertGreaterEqual(data["count"], 15)
        self.assertEqual(len(data["recognizers"]), data["count"])

    def test_recognizers_table(self):
        code, out, _ = self._capture(["recognizers"])
        self.assertEqual(code, 0)
        self.assertIn("recognizers", out)
        self.assertIn("CREDIT_CARD", out)

    def test_redact_cli(self):
        code, out, _ = self._capture(["redact", DEEP_LOG])
        self.assertEqual(code, 0)
        self.assertIn("[REDACTED", out)
        self.assertNotIn("536-42-7188", out)

    def test_no_context_flag(self):
        code, out, _ = self._capture(
            ["scan", DEEP_LOG, "--no-context", "--format", "json"])
        self.assertEqual(code, 0)
        data = json.loads(out)
        for r in data["reports"]:
            for f in r["findings"]:
                self.assertFalse(f["context_boosted"])


if __name__ == "__main__":
    unittest.main()
