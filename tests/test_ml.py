"""
Tests for the ML model check.

Run from the project folder with:
    python3 -m unittest discover tests
"""

import json
import tempfile
import unittest
from pathlib import Path

from detector.ml import ModelError, analyze_ml, load_model, phishing_probability
from detector.parser import parse_email
from detector.scoring import analyze_email

ROOT = Path(__file__).parent.parent
SAMPLES = ROOT / "samples"


class TestModel(unittest.TestCase):

    def test_matches_scikit_learn(self):
        # ml/train_model.py saved 200 test emails with scikit-learn's answers.
        # Our hand-written math must give the same answers.
        rows = json.loads((ROOT / "ml" / "parity_check.json").read_text())
        for row in rows:
            self.assertAlmostEqual(phishing_probability(row["text"]), row["prob"], places=4)

    def test_obvious_spam_scores_high(self):
        self.assertGreater(phishing_probability(
            "Earn guaranteed returns. Double your money in 7 days. Click here now."), 0.9)

    def test_normal_chat_scores_low(self):
        self.assertLess(phishing_probability(
            "Thanks for the PR. I left a few comments. Once fixed it looks good to merge."), 0.2)

    def test_never_more_than_low(self):
        # The model is experimental. It must never produce medium or high.
        for f in sorted(SAMPLES.glob("*.eml")):
            for finding in analyze_ml(parse_email(f.read_bytes())):
                self.assertIn(finding.severity, ("info", "low"))

    def test_legit_sample_still_low_risk_overall(self):
        # The model wrongly likes to flag this one. The overall verdict must hold.
        report = analyze_email(parse_email((SAMPLES / "sample_legit.eml").read_bytes()))
        self.assertEqual(report.verdict, "Low risk")


class TestModelFileSafety(unittest.TestCase):

    def test_rejects_missing_fields(self):
        with tempfile.TemporaryDirectory() as d:
            bad = Path(d) / "bad.json"
            bad.write_text(json.dumps({"version": 1}))
            with self.assertRaises(ModelError):
                load_model.__wrapped__(bad)

    def test_rejects_missing_file(self):
        with self.assertRaises(ModelError):
            load_model.__wrapped__(Path("/nonexistent/model.json"))


if __name__ == "__main__":
    unittest.main()
