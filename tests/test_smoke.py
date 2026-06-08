"""Smoke tests for PIICOMB. Standard library only, no network."""

import io
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from piicomb import TOOL_NAME, TOOL_VERSION, scan_text, redact_text  # noqa: E402
from piicomb.core import luhn_ok, valid_ssn, valid_card, valid_dob, scan_path  # noqa: E402
from piicomb import cli  # noqa: E402

DEMO = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "demos", "01-basic", "customer_export.csv",
)


class TestMeta(unittest.TestCase):
    def test_identity(self):
        self.assertEqual(TOOL_NAME, "piicomb")
        self.assertRegex(TOOL_VERSION, r"^\d+\.\d+\.\d+$")


class TestValidators(unittest.TestCase):
    def test_luhn(self):
        self.assertTrue(luhn_ok("4111111111111111"))   # valid Visa test number
        self.assertFalse(luhn_ok("1234567890123456"))  # fails checksum

    def test_card(self):
        self.assertTrue(valid_card("378282246310005"))   # Amex (15)
        self.assertFalse(valid_card("1234 5678 9012 3456"))

    def test_ssn(self):
        self.assertTrue(valid_ssn("536-42-7188"))
        self.assertFalse(valid_ssn("000-12-3456"))   # area 000
        self.assertFalse(valid_ssn("666-12-3456"))   # area 666
        self.assertFalse(valid_ssn("111-11-1111"))   # all same digit

    def test_dob(self):
        self.assertTrue(valid_dob("03/14/1987"))
        self.assertFalse(valid_dob("02/30/1991"))


class TestScanText(unittest.TestCase):
    def test_detects_each_type(self):
        text = (
            "email a@b.com phone (415) 555-0142 ssn 536-42-7188 "
            "card 4111 1111 1111 1111 dob 03/14/1987 "
            "Passport No: X12345678 DL number: D4821997"
        )
        labels = {f.label for f in scan_text(text)}
        for expected in ("EMAIL", "PHONE", "SSN", "CREDIT_CARD", "DOB",
                         "US_PASSPORT", "DRIVER_LICENSE"):
            self.assertIn(expected, labels, f"missing {expected}")

    def test_decoys_rejected(self):
        text = "bad ssn 000-12-3456 bad card 1234 5678 9012 3456 bad dob 02/30/1991"
        labels = {f.label for f in scan_text(text)}
        self.assertNotIn("SSN", labels)
        self.assertNotIn("CREDIT_CARD", labels)
        self.assertNotIn("DOB", labels)

    def test_min_score_filters(self):
        text = "phone 415-555-0142 email a@b.com"
        high = scan_text(text, min_score=0.9)
        labels = {f.label for f in high}
        self.assertIn("EMAIL", labels)       # 0.95
        self.assertNotIn("PHONE", labels)    # 0.7

    def test_line_numbers(self):
        text = "line one\nssn 536-42-7188\n"
        findings = scan_text(text)
        self.assertEqual(findings[0].line, 2)


class TestRedact(unittest.TestCase):
    def test_masks_values(self):
        out = redact_text("contact a@b.com now")
        self.assertNotIn("a@b.com", out)
        self.assertIn("[REDACTED", out)

    def test_keeps_non_pii(self):
        self.assertEqual(redact_text("nothing here"), "nothing here")


class TestScanPath(unittest.TestCase):
    def test_demo_file(self):
        result = scan_path(DEMO)
        self.assertGreater(result.total_findings, 0)
        counts = result.label_counts()
        self.assertIn("EMAIL", counts)
        self.assertIn("CREDIT_CARD", counts)

    def test_missing_path_raises(self):
        with self.assertRaises(FileNotFoundError):
            scan_path(os.path.join(os.path.dirname(DEMO), "nope_missing.xyz"))


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

    def test_scan_json(self):
        code, out, _ = self._capture(["scan", DEMO, "--format", "json"])
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertIn("summary", data)
        self.assertGreater(data["summary"]["total_findings"], 0)

    def test_scan_table(self):
        code, out, _ = self._capture(["scan", DEMO, "--format", "table"])
        self.assertEqual(code, 0)
        self.assertIn("finding(s)", out)

    def test_fail_on_find(self):
        code, _, _ = self._capture(["scan", DEMO, "--fail-on-find"])
        self.assertEqual(code, 1)

    def test_missing_path_nonzero(self):
        code, _, err = self._capture(["scan", "does_not_exist_123.txt"])
        self.assertEqual(code, 1)
        self.assertIn("no such file", err)

    def test_bad_min_score(self):
        code, _, _ = self._capture(["scan", DEMO, "--min-score", "5"])
        self.assertEqual(code, 2)

    def test_redact(self):
        code, out, _ = self._capture(["redact", DEMO])
        self.assertEqual(code, 0)
        self.assertIn("[REDACTED", out)
        self.assertNotIn("jane.doe@example.com", out)


if __name__ == "__main__":
    unittest.main()
