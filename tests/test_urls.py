"""
Tests for URL analysis.

Run from the project folder with:
    python3 -m unittest discover tests
"""

import unittest
from pathlib import Path

from detector.parser import Link, parse_email
from detector.urls import analyze_urls, check_link, defang

SAMPLES = Path(__file__).parent.parent / "samples"


def messages(findings):
    return " | ".join(f.message for f in findings)


class TestLinkTricks(unittest.TestCase):

    def test_text_and_target_dont_match(self):
        f = check_link(Link(url="https://evil.example/x", display_text="www.chase.com", source="html"))
        self.assertIn("really goes to", messages(f))

    def test_ip_address(self):
        f = check_link(Link(url="http://203.0.113.77/login"))
        self.assertIn("raw IP address", messages(f))

    def test_at_trick(self):
        f = check_link(Link(url="https://paypal.com@pay-portal.example/x"))
        self.assertIn("'@' trick", messages(f))

    def test_brand_as_subdomain(self):
        f = check_link(Link(url="https://paypal.com.secure-checkout.example/login"))
        self.assertIn("The real domain is always at the end", messages(f))

    def test_javascript_link(self):
        f = check_link(Link(url="javascript:alert(1)"))
        self.assertEqual(f[0].severity, "high")

    def test_shortener(self):
        f = check_link(Link(url="https://bit.ly/abc"))
        self.assertIn("shortener", messages(f))

    def test_lookalike_link_domain(self):
        f = check_link(Link(url="https://paypa1.com/login"))
        self.assertIn("look-alike", messages(f))

    def test_links_sample_catches_everything(self):
        email = parse_email((SAMPLES / "sample_phish_links.eml").read_bytes())
        text = messages(analyze_urls(email))
        for clue in ["raw IP", "'@' trick", "always at the end", "shortener", "javascript"]:
            self.assertIn(clue, text)


class TestNoFalseAlarms(unittest.TestCase):

    def test_matching_text_and_link(self):
        f = check_link(Link(url="https://www.paypal.com/activity",
                            display_text="paypal.com", source="html"))
        self.assertEqual(f, [])

    def test_plain_words_as_link_text(self):
        f = check_link(Link(url="https://www.amazon.com/orders",
                            display_text="View your orders", source="html"))
        self.assertEqual(f, [])

    def test_mailto_and_anchor_ignored(self):
        self.assertEqual(check_link(Link(url="mailto:help@shop.example")), [])
        self.assertEqual(check_link(Link(url="#top")), [])

    def test_subdomain_of_same_site(self):
        f = check_link(Link(url="https://track.shop.example/1",
                            display_text="www.shop.example", source="html"))
        self.assertEqual(f, [])


class TestDefang(unittest.TestCase):

    def test_defang(self):
        self.assertEqual(defang("https://bad.com/a.php"), "hxxps://bad[.]com/a[.]php")


if __name__ == "__main__":
    unittest.main()
