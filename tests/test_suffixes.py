"""
Tests for the Public Suffix List lookup, and for the checks that depend on it.

Before this was added, domains were cut to their last two parts, so
'bank.co.uk' became 'co.uk' and every UK company looked like the same site.

Run from the project folder with:
    python3 -m unittest discover tests
"""

import unittest

from detector.headers import analyze_headers, base_domain
from detector.parser import Link, parse_email
from detector.sender import analyze_sender
from detector.suffixes import public_suffix, registrable_domain
from detector.urls import check_link


def messages(findings):
    return " | ".join(f.message for f in findings)


class TestRegistrableDomain(unittest.TestCase):
    """Cases taken from the official test list at publicsuffix.org."""

    def check(self, domain, expected):
        self.assertEqual(registrable_domain(domain), expected, domain)

    def test_simple(self):
        self.check("example.com", "example.com")
        self.check("b.example.com", "example.com")
        self.check("a.b.example.com", "example.com")

    def test_multi_part_suffix(self):
        self.check("bank.co.uk", "bank.co.uk")
        self.check("mail.bank.co.uk", "bank.co.uk")
        self.check("shop.com.au", "shop.com.au")
        self.check("www.example.co.jp", "example.co.jp")

    def test_suffix_alone_is_returned_unchanged(self):
        self.check("co.uk", "co.uk")
        self.check("com", "com")

    def test_wildcard_and_exception_rules(self):
        # '*.ck' makes every 'x.ck' a suffix, but '!www.ck' is an exception.
        self.assertEqual(public_suffix("test.ck"), "test.ck")
        self.check("b.test.ck", "b.test.ck")
        self.check("a.b.test.ck", "b.test.ck")
        self.check("www.ck", "www.ck")
        self.check("www.www.ck", "www.ck")

    def test_unknown_ending_uses_last_label(self):
        # Reserved test domains like '.example' aren't on the list.
        self.check("mail.shop.example", "shop.example")

    def test_private_suffixes(self):
        # Anyone can get a 'something.github.io', so each one is its own owner.
        self.check("evil.github.io", "evil.github.io")
        self.check("www.evil.github.io", "evil.github.io")

    def test_punycode_rule(self):
        # The list stores some rules in Unicode; email domains use 'xn--' form.
        self.check("shop.xn--fiqs8s", "shop.xn--fiqs8s")        # .中国
        self.check("www.shop.xn--fiqs8s", "shop.xn--fiqs8s")

    def test_messy_input(self):
        self.check("MAIL.Bank.CO.UK.", "bank.co.uk")
        self.check("", "")

    def test_base_domain_uses_list(self):
        self.assertEqual(base_domain("mail.bank.co.uk"), "bank.co.uk")


class TestChecksThatWereBroken(unittest.TestCase):
    """Each of these was missed when 'bank.co.uk' turned into 'co.uk'."""

    def test_link_to_different_uk_site(self):
        f = check_link(Link(url="https://login.evil.co.uk/x",
                            display_text="www.mybank.co.uk", source="html"))
        self.assertIn("really goes to", messages(f))

    def test_link_to_same_uk_site_is_fine(self):
        f = check_link(Link(url="https://secure.mybank.co.uk/x",
                            display_text="www.mybank.co.uk", source="html"))
        self.assertNotIn("really goes to", messages(f))

    def test_link_to_different_github_pages_site(self):
        f = check_link(Link(url="https://evil.github.io/login",
                            display_text="mybank.github.io", source="html"))
        self.assertIn("really goes to", messages(f))

    def test_lookalike_on_uk_domain(self):
        raw = b"From: <service@paypa1.co.uk>\nSubject: t\nMessage-ID: <t@t>\n\nhi\n"
        findings = analyze_sender(parse_email(raw))
        self.assertTrue(any("look-alike" in f.message for f in findings))

    def test_reply_to_another_uk_company(self):
        raw = (b"From: <billing@mybank.co.uk>\n"
               b"Reply-To: <billing@thief.co.uk>\n"
               b"Subject: t\nMessage-ID: <t@t>\n\nhi\n")
        _, findings = analyze_headers(parse_email(raw))
        self.assertTrue(any(f.check == "Reply-To" for f in findings))


if __name__ == "__main__":
    unittest.main()
