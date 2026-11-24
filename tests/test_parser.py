"""
Tests for the email parser.

Run from the project folder with:
    python3 -m unittest discover tests
"""

import unittest
from pathlib import Path

from detector.parser import MAX_EMAIL_SIZE, EmailParseError, parse_email

SAMPLE = Path(__file__).parent.parent / "samples" / "sample_phish.eml"


class TestParser(unittest.TestCase):

    def setUp(self):
        self.email = parse_email(SAMPLE.read_bytes())

    def test_reads_sender_details(self):
        self.assertEqual(self.email.from_name, "Northbridge Bank Security")
        self.assertEqual(self.email.from_address, "security@northbridge-bank-alerts.example")
        self.assertEqual(self.email.reply_to, "northbridge.support.team@freemail.example")

    def test_reads_auth_results(self):
        self.assertEqual(len(self.email.auth_results), 1)
        self.assertIn("spf=fail", self.email.auth_results[0])

    def test_finds_hidden_link_target(self):
        html_links = [l for l in self.email.links if l.source == "html"]
        self.assertEqual(len(html_links), 1)
        # What the reader sees vs. where it really goes
        self.assertIn("northbridgebank.example", html_links[0].display_text)
        self.assertIn("northbridge-verify.example", html_links[0].url)

    def test_fingerprints_attachment(self):
        self.assertEqual(len(self.email.attachments), 1)
        att = self.email.attachments[0]
        self.assertEqual(att.filename, "Account_Statement.pdf")
        self.assertEqual(len(att.sha256), 64)

    def test_rejects_empty_input(self):
        with self.assertRaises(EmailParseError):
            parse_email(b"")

    def test_rejects_non_email(self):
        with self.assertRaises(EmailParseError):
            parse_email(b"just some random text, not an email")

    def test_rejects_huge_input(self):
        with self.assertRaises(EmailParseError):
            parse_email(b"x" * (MAX_EMAIL_SIZE + 1))


if __name__ == "__main__":
    unittest.main()
