"""
Tests for sender analysis.

Run from the project folder with:
    python3 -m unittest discover tests
"""

import unittest
from pathlib import Path

from detector.parser import parse_email
from detector.sender import analyze_sender, edit_distance, undo_lookalikes

SAMPLES = Path(__file__).parent.parent / "samples"


def make_email(from_header, reply_to=None):
    """Build a tiny fake email in memory so each test can try one trick."""
    raw = f"From: {from_header}\n"
    if reply_to:
        raw += f"Reply-To: {reply_to}\n"
    raw += "Subject: test\nMessage-ID: <t@test>\n\nhello\n"
    return parse_email(raw.encode())


def worst(findings):
    order = ["info", "low", "medium", "high"]
    return max((f.severity for f in findings), key=order.index, default="none")


class TestSenderTricks(unittest.TestCase):

    def test_character_swap(self):
        findings = analyze_sender(make_email('"PayPal" <service@paypa1.com>'))
        self.assertEqual(worst(findings), "high")
        self.assertTrue(any("look-alike" in f.message for f in findings))

    def test_rn_looks_like_m(self):
        findings = analyze_sender(make_email("<alerts@rnicrosoft.com>"))
        self.assertEqual(worst(findings), "high")

    def test_typo_squat(self):
        findings = analyze_sender(make_email("<orders@amazom.com>"))
        self.assertEqual(worst(findings), "medium")

    def test_brand_inside_fake_domain(self):
        findings = analyze_sender(make_email("<noreply@paypal-account-verify.com>"))
        self.assertTrue(any("contains the brand name" in f.message for f in findings))

    def test_punycode(self):
        findings = analyze_sender(make_email("<support@xn--pple-43d.com>"))
        self.assertEqual(worst(findings), "high")

    def test_brand_display_name_wrong_domain(self):
        findings = analyze_sender(make_email('"Microsoft Account Team" <alerts@random-host.com>'))
        self.assertTrue(any(f.check == "Display name" for f in findings))

    def test_hidden_email_in_display_name(self):
        findings = analyze_sender(make_email('"support@paypal.com" <x9@evil-site.com>'))
        self.assertTrue(any("real address" in f.message for f in findings))

    def test_official_name_from_gmail(self):
        findings = analyze_sender(make_email('"IT Helpdesk" <it.helpdesk.2026@gmail.com>'))
        self.assertTrue(any(f.check == "Free email" for f in findings))

    def test_phish_sample(self):
        email = parse_email((SAMPLES / "sample_phish.eml").read_bytes())
        self.assertEqual(worst(analyze_sender(email)), "high")


class TestNoFalseAlarms(unittest.TestCase):
    """A detector that cries wolf is useless. These must stay quiet."""

    def test_real_paypal(self):
        self.assertEqual(analyze_sender(make_email('"PayPal" <service@paypal.com>')), [])

    def test_real_subdomain(self):
        self.assertEqual(analyze_sender(make_email('"Amazon" <ship@email.amazon.com>')), [])

    def test_short_brand_inside_word(self):
        # "groups" contains "ups" but has nothing to do with UPS.
        self.assertEqual(analyze_sender(make_email("<news@groups.example>")), [])

    def test_friend_on_gmail(self):
        self.assertEqual(analyze_sender(make_email('"Maria Lopez" <maria.l@gmail.com>')), [])

    def test_legit_sample(self):
        email = parse_email((SAMPLES / "sample_legit.eml").read_bytes())
        self.assertEqual(analyze_sender(email), [])


class TestHelpers(unittest.TestCase):

    def test_edit_distance(self):
        self.assertEqual(edit_distance("amazon", "amazom"), 1)
        self.assertEqual(edit_distance("paypal", "paypal"), 0)

    def test_undo_lookalikes(self):
        self.assertEqual(undo_lookalikes("paypa1"), "paypal")
        self.assertEqual(undo_lookalikes("rnicrosoft"), "microsoft")


if __name__ == "__main__":
    unittest.main()
