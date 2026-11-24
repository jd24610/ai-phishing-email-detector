"""
Tests for wording analysis.

Run from the project folder with:
    python3 -m unittest discover tests
"""

import unittest
from pathlib import Path

from detector.language import analyze_language
from detector.parser import parse_email
from detector.scoring import analyze_email

SAMPLES = Path(__file__).parent.parent / "samples"


def email_with(body, subject="hello", html=False):
    ctype = "text/html" if html else "text/plain"
    raw = (f"From: <a@b.example>\nSubject: {subject}\nMessage-ID: <x@b.example>\n"
           f"Content-Type: {ctype}; charset=utf-8\n\n{body}\n")
    return parse_email(raw.encode("utf-8"))


def checks(findings):
    return {f.check for f in findings}


class TestScamWording(unittest.TestCase):

    def test_gift_card_scam(self):
        found = checks(analyze_language(email_with(
            "Buy 3 gift cards and keep this between us. Send me the codes.")))
        self.assertIn("Money request", found)
        self.assertIn("Secrecy", found)
        self.assertIn("Scam pattern", found)

    def test_account_suspended_phish(self):
        found = checks(analyze_language(email_with(
            "Your account has been suspended. Verify your identity within 24 hours.")))
        self.assertIn("Threat", found)
        self.assertIn("Credential request", found)
        self.assertIn("Urgency", found)

    def test_payment_change(self):
        found = checks(analyze_language(email_with(
            "Please note our new bank details for all future invoices.")))
        self.assertIn("Payment change", found)

    def test_invisible_characters_dont_hide_words(self):
        # "gift" with a zero-width space hidden inside it
        found = checks(analyze_language(email_with("Please buy gi​ft cards today.")))
        self.assertIn("Money request", found)

    def test_html_only_email(self):
        found = checks(analyze_language(email_with(
            "<p>You have <b>won</b>! Claim your prize now.</p>", html=True)))
        self.assertIn("Too good to be true", found)

    def test_ceo_fraud_sample_is_caught(self):
        report = analyze_email(parse_email((SAMPLES / "sample_ceo_fraud.eml").read_bytes()))
        self.assertEqual(report.verdict, "Likely phishing")


class TestNoFalseAlarms(unittest.TestCase):

    def test_normal_work_email(self):
        self.assertEqual(analyze_language(email_with(
            "Hi Joe, here are the notes from today's meeting. Talk soon.")), [])

    def test_password_changed_notice(self):
        # Real security notices mention passwords but don't ask you to enter one.
        self.assertEqual(analyze_language(email_with(
            "Your password was changed. If this wasn't you, contact support.")), [])

    def test_sale_email_is_only_low(self):
        findings = analyze_language(email_with("Big sale! Offer expires today."))
        self.assertTrue(all(f.severity == "low" for f in findings))

    def test_legit_sample(self):
        email = parse_email((SAMPLES / "sample_legit.eml").read_bytes())
        self.assertEqual(analyze_language(email), [])


if __name__ == "__main__":
    unittest.main()
