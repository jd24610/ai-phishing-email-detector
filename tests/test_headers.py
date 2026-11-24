"""
Tests for header analysis.

Run from the project folder with:
    python3 -m unittest discover tests
"""

import unittest
from pathlib import Path

from detector.headers import analyze_headers, base_domain, read_auth_results
from detector.parser import parse_email

SAMPLES = Path(__file__).parent.parent / "samples"


def severities(findings):
    return {f.check: f.severity for f in findings}


class TestHeaders(unittest.TestCase):

    def test_phish_sample_is_flagged(self):
        email = parse_email((SAMPLES / "sample_phish.eml").read_bytes())
        auth, findings = analyze_headers(email)
        self.assertEqual(auth, {"spf": "fail", "dkim": "none", "dmarc": "fail"})
        s = severities(findings)
        self.assertEqual(s["DMARC"], "high")
        self.assertEqual(s["SPF"], "medium")
        self.assertEqual(s["Reply-To"], "medium")

    def test_legit_sample_has_no_warnings(self):
        email = parse_email((SAMPLES / "sample_legit.eml").read_bytes())
        auth, findings = analyze_headers(email)
        self.assertEqual(auth, {"spf": "pass", "dkim": "pass", "dmarc": "pass"})
        # Only "info" findings allowed, no warnings.
        self.assertTrue(all(f.severity == "info" for f in findings))

    def test_only_top_auth_header_is_trusted(self):
        # An attacker added a fake "pass" header lower down. We must ignore it.
        headers = ["mx.me; spf=fail; dkim=fail; dmarc=fail",
                   "fake.example; spf=pass; dkim=pass; dmarc=pass"]
        self.assertEqual(read_auth_results(headers)["dmarc"], "fail")

    def test_missing_auth_is_not_treated_as_fail(self):
        self.assertEqual(read_auth_results([])["spf"], "missing")

    def test_base_domain(self):
        self.assertEqual(base_domain("mail.shop.example"), "shop.example")


if __name__ == "__main__":
    unittest.main()
