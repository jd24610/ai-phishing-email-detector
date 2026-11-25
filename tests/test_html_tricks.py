"""
Tests for HTML trick checks (login forms and hidden text).

Run from the project folder with:
    python3 -m unittest discover tests
"""

import unittest
from pathlib import Path

from detector.html_tricks import analyze_html
from detector.parser import parse_email
from detector.scoring import analyze_email

SAMPLES = Path(__file__).parent.parent / "samples"


def html_email(body):
    raw = ("From: <a@shop.example>\nSubject: t\nMessage-ID: <t@t>\n"
           "Content-Type: text/html; charset=utf-8\n\n" + body + "\n")
    return parse_email(raw.encode("utf-8"))


def check(body):
    return analyze_html(html_email(body))


def warnings(findings):
    """Everything except info notes."""
    return [f for f in findings if f.severity != "info"]


def messages(findings):
    return " | ".join(f.message for f in findings)


FILLER = "This is ordinary filler text about nothing in particular. " * 8   # ~470 chars


class TestForms(unittest.TestCase):

    def test_password_form_is_high(self):
        f = check('<form action="https://collect.example/go">'
                  '<input name="user"><input type="password" name="pw"></form>')
        self.assertEqual(f[0].severity, "high")
        self.assertIn("collect.example", f[0].message)
        self.assertIn("'pw'", f[0].message)

    def test_card_number_field_is_high(self):
        f = check('<form><input name="card_number"><input name="cvv"></form>')
        self.assertEqual(f[0].severity, "high")

    def test_ordinary_form_is_medium(self):
        f = check('<form action="https://survey.example/s"><input name="feedback">'
                  '<textarea name="comments"></textarea></form>')
        self.assertEqual([x.severity for x in f], ["medium"])
        self.assertIn("2 field(s)", f[0].message)

    def test_form_with_only_buttons_is_ignored(self):
        # e.g. an unsubscribe button: nothing to type into.
        f = check('<form action="https://shop.example/unsub">'
                  '<input type="hidden" name="id" value="1"><input type="submit"></form>')
        self.assertEqual(warnings(f), [])

    def test_password_box_outside_a_form(self):
        f = check('<p>Password: <input type="password" name="p"></p>')
        self.assertEqual(f[0].severity, "high")

    def test_zip_code_is_not_sensitive(self):
        f = check('<form><input name="zipcode"><input name="spinner"></form>')
        self.assertEqual([x.severity for x in f], ["medium"])

    def test_form_action_is_never_visited(self):
        # The check must work offline: an unreachable action is fine.
        f = check('<form action="https://does-not-exist.invalid/x">'
                  '<input type="password" name="p"></form>')
        self.assertIn("does-not-exist.invalid", f[0].message)


class TestHiddenText(unittest.TestCase):

    def test_newsletter_preheader_is_not_a_warning(self):
        f = check('<div style="display:none;max-height:0;overflow:hidden">'
                  'Our winter sale starts today&zwnj;&nbsp;&zwnj;&nbsp;</div><p>Hi there</p>')
        self.assertEqual(warnings(f), [])
        self.assertEqual(f[0].severity, "info")

    def test_lots_of_display_none_text(self):
        f = check(f'<p>Pay now</p><div style="display: none">{FILLER}</div>')
        self.assertIn("display:none", messages(warnings(f)))

    def test_white_on_white(self):
        f = check(f'<body bgcolor="#FFFFFF"><p style="color:white">{FILLER}</p></body>')
        self.assertIn("same color as its background", messages(warnings(f)))

    def test_rgb_and_short_hex_colors_match(self):
        f = check(f'<div style="background-color:#fff">'
                  f'<span style="color:rgb(255, 255, 255)">{FILLER}</span></div>')
        self.assertIn("same color as its background", messages(warnings(f)))

    def test_white_text_on_dark_background_is_fine(self):
        f = check(f'<td style="background:#1a1a1a"><span style="color:#ffffff">{FILLER}</span></td>')
        self.assertEqual(f, [])

    def test_tiny_font_and_zero_opacity(self):
        for style in ("font-size:0px", "font-size: 1px", "opacity:0", "visibility:hidden"):
            with self.subTest(style=style):
                f = check(f'<span style="{style}">{FILLER}</span>')
                self.assertTrue(warnings(f), style)

    def test_normal_styling_is_fine(self):
        f = check(f'<p style="font-size:14px;color:#333;opacity:0.9">{FILLER}</p>')
        self.assertEqual(f, [])

    def test_hidden_text_inside_a_word(self):
        f = check('<p>Log in to Pay<span style="font-size:0">zz</span>Pal today</p>')
        self.assertIn("'PayPal' on screen is really 'PayzzPal'", messages(f))

    def test_hidden_text_between_words_is_not_a_split(self):
        f = check('<p>Hello <span style="display:none">x</span> world</p>')
        self.assertNotIn("inside words", messages(f))

    def test_text_in_style_and_script_is_ignored(self):
        f = check(f'<style>.a {{ display:none }} /* {FILLER} */</style><p>Hi</p>')
        self.assertEqual(f, [])

    def test_hidden_parent_hides_children(self):
        f = check(f'<div style="display:none"><p><b>{FILLER}</b></p></div>')
        self.assertTrue(warnings(f))

    def test_closing_a_hidden_element_ends_hiding(self):
        f = check(f'<span style="display:none">x</span><p>{FILLER}</p>')
        self.assertEqual(warnings(f), [])


class TestRobustness(unittest.TestCase):

    def test_plain_text_email_has_no_findings(self):
        raw = b"From: <a@b.example>\nSubject: t\nMessage-ID: <t@t>\n\nHello\n"
        self.assertEqual(analyze_html(parse_email(raw)), [])

    def test_broken_html_does_not_crash(self):
        for body in ['<div style="display:none"><p>unclosed', '</span></div></p>',
                     '<form><input type=password', '<<<>>>', '<p style=";;;:::">x</p>']:
            with self.subTest(body=body):
                check(body)  # must not raise

    def test_huge_html_is_capped(self):
        f = check("<p>" + "a" * 2_000_000 + "</p>")
        self.assertEqual(f, [])


class TestSample(unittest.TestCase):

    def test_html_tricks_sample(self):
        email = parse_email((SAMPLES / "sample_phish_html.eml").read_bytes())
        report = analyze_email(email)
        self.assertEqual(report.verdict, "Likely phishing")
        found = report.by_category["HTML tricks"]
        self.assertEqual(sorted(f.severity for f in found), ["high", "medium", "medium"])
        # Every other category is quiet, so this verdict comes from the HTML check.
        others = sum(p for c, p in report.category_points.items() if c != "HTML tricks")
        self.assertLess(others, 20)


if __name__ == "__main__":
    unittest.main()
