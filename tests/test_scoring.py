"""
Tests for risk scoring.

Run from the project folder with:
    python3 -m unittest discover tests
"""

import unittest
from pathlib import Path

from detector.findings import Finding
from detector.parser import parse_email
from detector.scoring import analyze_email, score_findings, top_reasons, verdict_for

SAMPLES = Path(__file__).parent.parent / "samples"


def report_for(name):
    return analyze_email(parse_email((SAMPLES / name).read_bytes()))


def f(severity):
    return Finding("Test", severity, f"a {severity} finding")


class TestVerdictsOnSamples(unittest.TestCase):

    def test_legit_is_low_risk(self):
        r = report_for("sample_legit.eml")
        self.assertEqual(r.verdict, "Low risk")
        # Not exactly 0: the experimental ML model gives a known false "low" (5 pts) here.
        self.assertLess(r.score, 20)

    def test_all_phish_samples_are_likely_phishing(self):
        for name in ["sample_phish.eml", "sample_phish_links.eml", "sample_phish_attach.eml"]:
            with self.subTest(sample=name):
                self.assertEqual(report_for(name).verdict, "Likely phishing")


class TestScoringRules(unittest.TestCase):

    def test_one_medium_alone_stays_low_risk(self):
        # Example: apply.com is one letter from apple.com. That alone shouldn't scare anyone.
        score, _ = score_findings({"Sender": [f("medium")]})
        self.assertEqual(verdict_for(score), "Low risk")

    def test_one_high_is_suspicious(self):
        score, _ = score_findings({"Links": [f("high")]})
        self.assertEqual(verdict_for(score), "Suspicious")

    def test_category_cap(self):
        # Ten small warnings in one category can't go over the cap.
        score, points = score_findings({"Links": [f("low")] * 10 + [f("high")] * 3})
        self.assertEqual(points["Links"], 50)

    def test_agreement_bonus(self):
        alone, _ = score_findings({"Sender": [f("medium")]})
        together, _ = score_findings({"Sender": [f("medium")], "Links": [f("medium")]})
        self.assertEqual(together, alone + 15 + 10)

    def test_info_findings_add_nothing(self):
        score, _ = score_findings({"Headers": [f("info")] * 5})
        self.assertEqual(score, 0)

    def test_score_never_over_100(self):
        groups = {c: [f("high")] * 5 for c in ["Headers", "Sender", "Links", "Attachments"]}
        score, _ = score_findings(groups)
        self.assertEqual(score, 100)

    def test_top_reasons_highest_first(self):
        reasons = top_reasons({"A": [f("low"), f("info")], "B": [f("high"), f("medium")]})
        self.assertEqual([r.severity for r in reasons], ["high", "medium", "low"])


class TestHonesty(unittest.TestCase):

    def test_notes_mention_what_was_not_checked(self):
        r = report_for("sample_phish_links.eml")
        self.assertTrue(any("offline" in n for n in r.notes))


if __name__ == "__main__":
    unittest.main()
