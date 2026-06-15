"""Hardening tests for PIICOMB — edge cases, empty input, and error paths.

Standard library only, no network.
"""

from __future__ import annotations

import datetime
import io
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from piicomb.core import (  # noqa: E402
    scan_text,
    scan_path,
    redact_text,
    valid_dob,
)
from piicomb import cli  # noqa: E402
from piicomb.cli import _parse_only  # noqa: E402


class TestValidDobCurrentYear(unittest.TestCase):
    """valid_dob must accept dates in the current calendar year."""

    def test_current_year_accepted(self):
        year = datetime.date.today().year
        # Use a definitively valid date (Jan 15) in the current year.
        self.assertTrue(valid_dob(f"01/15/{year}"), f"01/15/{year} should be valid")

    def test_future_year_rejected(self):
        future = datetime.date.today().year + 1
        self.assertFalse(valid_dob(f"01/15/{future}"), f"01/15/{future} should be invalid")

    def test_prehistoric_year_rejected(self):
        self.assertFalse(valid_dob("03/14/1899"))


class TestScanTextEdgeCases(unittest.TestCase):
    """scan_text must handle degenerate inputs without crashing."""

    def test_empty_string_returns_empty_list(self):
        result = scan_text("")
        self.assertEqual(result, [])

    def test_whitespace_only_returns_empty_list(self):
        result = scan_text("   \n\t  ")
        self.assertEqual(result, [])

    def test_only_filter_empty_still_returns_no_crash(self):
        # only=[] is falsy so it is treated as None (all recognizers run).
        # The important guarantee is that it does NOT raise.
        result = scan_text("nothing sensitive", only=[])
        self.assertIsInstance(result, list)

    def test_min_score_one_returns_only_ceiling_hits(self):
        # A min_score of 1.0 should never raise and should just return fewer findings.
        result = scan_text("email a@b.com phone 415-555-0142", min_score=1.0)
        self.assertIsInstance(result, list)


class TestRedactTextEdgeCases(unittest.TestCase):
    def test_empty_string(self):
        self.assertEqual(redact_text(""), "")

    def test_no_pii_unchanged(self):
        text = "the quick brown fox"
        self.assertEqual(redact_text(text), text)


class TestScanPathEdgeCases(unittest.TestCase):
    def test_explicit_empty_paths_iterable(self):
        # paths=[] must return an empty ScanResult, not raise.
        result = scan_path("", paths=[])
        self.assertEqual(result.total_findings, 0)
        self.assertEqual(len(result.reports), 0)

    def test_missing_path_raises_file_not_found(self):
        with self.assertRaises(FileNotFoundError):
            scan_path("/no/such/path/exists_xyz")

    def test_single_nonexistent_file_in_paths_produces_error_report(self):
        result = scan_path("", paths=["/no/such/file_xyz.txt"])
        self.assertEqual(len(result.reports), 1)
        self.assertIsNotNone(result.reports[0].error)


class TestParseOnlyEdgeCases(unittest.TestCase):
    """_parse_only must reject empty-after-strip label strings."""

    def test_none_returns_none(self):
        self.assertIsNone(_parse_only(None))

    def test_empty_string_returns_none(self):
        self.assertIsNone(_parse_only(""))

    def test_commas_only_raises(self):
        with self.assertRaises(ValueError) as ctx:
            _parse_only(",,,")
        self.assertIn("no valid labels", str(ctx.exception))

    def test_spaces_only_raises(self):
        with self.assertRaises(ValueError):
            _parse_only("  ,  ,  ")

    def test_unknown_label_raises(self):
        with self.assertRaises(ValueError) as ctx:
            _parse_only("EMAIL,BOGUS_LABEL")
        self.assertIn("unknown recognizer", str(ctx.exception))


class TestCLIHardeningEdgePaths(unittest.TestCase):
    def _capture(self, argv):
        out, err = io.StringIO(), io.StringIO()
        old_out, old_err = sys.stdout, sys.stderr
        sys.stdout, sys.stderr = out, err
        try:
            code = cli.main(argv)
        finally:
            sys.stdout, sys.stderr = old_out, old_err
        return code, out.getvalue(), err.getvalue()

    def test_only_commas_exits_2(self):
        """--only with only commas should return exit code 2 with a clear message."""
        code, _, err = self._capture(["scan", ".", "--only", ",,,"])
        self.assertEqual(code, 2)
        self.assertIn("error:", err)

    def test_only_unknown_label_exits_2(self):
        code, _, err = self._capture(["scan", ".", "--only", "TOTALLY_BOGUS"])
        self.assertEqual(code, 2)
        self.assertIn("unknown recognizer", err)

    def test_redact_missing_file_exits_1(self):
        code, _, err = self._capture(["redact", "/no/such/file_xyz.txt"])
        self.assertEqual(code, 1)
        self.assertIn("error:", err)

    def test_scan_missing_file_exits_1(self):
        code, _, err = self._capture(["scan", "/no/such/dir_xyz"])
        self.assertEqual(code, 1)
        self.assertIn("error:", err)

    def test_min_score_out_of_range_exits_2(self):
        code, _, err = self._capture(["scan", ".", "--min-score", "1.5"])
        self.assertEqual(code, 2)
        self.assertIn("--min-score", err)


if __name__ == "__main__":
    unittest.main()
