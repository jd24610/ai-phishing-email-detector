"""
Risk scoring.

Every check so far produces a list of findings. A user doesn't want 12
warnings. They want one answer: should I trust this email?

This file runs all the checks, turns their findings into a score from
0 to 100, and picks a verdict with the top reasons.

How the score works:
- Each finding is worth points based on severity.
- Each category is capped, so lots of small warnings in one area
  can't add up to a scary score on their own.
- If several DIFFERENT categories find problems, we add a bonus.
  Independent checks agreeing is much stronger evidence.
- Passing checks (like DMARC pass) never LOWER the score. Scammers can
  pass DMARC on their own domains, so a pass proves very little.

The verdict wording is careful on purpose. "Likely phishing" is not
"confirmed phishing." This tool gives evidence, not certainty.
"""

from dataclasses import dataclass, field

from detector.attachments import analyze_attachments
from detector.headers import analyze_headers
from detector.language import analyze_language
from detector.ml import analyze_ml
from detector.sender import analyze_sender
from detector.urls import analyze_urls

POINTS = {"info": 0, "low": 5, "medium": 15, "high": 30}
CATEGORY_CAP = 50
AGREEMENT_BONUS = 10  # added when 2+ categories have medium or high findings

SUSPICIOUS_AT = 20
LIKELY_AT = 50

SEVERITY_ORDER = {"high": 3, "medium": 2, "low": 1, "info": 0}

ADVICE = {
    "Low risk": "No strong warning signs found. That isn't a guarantee. "
                "If the email asks for money or passwords, still double-check.",
    "Suspicious": "Some warning signs found. Don't click links or open attachments. "
                  "Contact the sender another way (their real website or phone number) to confirm.",
    "Likely phishing": "Several strong warning signs found. Don't click, reply, or open "
                       "anything. Report it to your IT team or email provider and delete it.",
}


@dataclass
class Report:
    score: int
    verdict: str
    advice: str
    top_reasons: list                                   # the most serious findings
    by_category: dict = field(default_factory=dict)     # every finding, grouped
    category_points: dict = field(default_factory=dict)
    auth: dict = field(default_factory=dict)            # SPF / DKIM / DMARC results
    notes: list = field(default_factory=list)           # limits of this analysis


def score_findings(by_category):
    """
    Turn grouped findings into (score, points_per_category).
    by_category looks like {"Headers": [Finding, ...], "Links": [...]}
    """
    category_points = {}
    for category, findings in by_category.items():
        raw = sum(POINTS[f.severity] for f in findings)
        category_points[category] = min(raw, CATEGORY_CAP)

    total = sum(category_points.values())

    serious_categories = [
        c for c, findings in by_category.items()
        if any(f.severity in ("medium", "high") for f in findings)
    ]
    if len(serious_categories) >= 2:
        total += AGREEMENT_BONUS

    return min(total, 100), category_points


def verdict_for(score):
    if score >= LIKELY_AT:
        return "Likely phishing"
    if score >= SUSPICIOUS_AT:
        return "Suspicious"
    return "Low risk"


def top_reasons(by_category, limit=3):
    """The most serious non-info findings, highest first."""
    everything = [f for findings in by_category.values() for f in findings
                  if f.severity != "info"]
    everything.sort(key=lambda f: SEVERITY_ORDER[f.severity], reverse=True)
    return everything[:limit]


def analyze_email(email):
    """Run every check on a ParsedEmail and return one Report."""
    auth, header_findings = analyze_headers(email)

    by_category = {
        "Headers": header_findings,
        "Sender": analyze_sender(email),
        "Links": analyze_urls(email),
        "Attachments": analyze_attachments(email),
        "Wording": analyze_language(email),
        "ML model": analyze_ml(email),
    }

    score, category_points = score_findings(by_category)
    verdict = verdict_for(score)

    # Be honest about what we could NOT check.
    notes = []
    if all(v == "missing" for v in auth.values()):
        notes.append("No SPF/DKIM/DMARC results were in this email, so sender checks are limited.")
    if email.links:
        notes.append("Links were checked offline only. They have not been checked against "
                     "online blocklists yet.")
    if email.attachments:
        notes.append("Attachments were not scanned for malware, only their names and file types.")
    notes.append("Wording was checked with keyword rules only. Scams that use unusual "
                 "phrasing can slip past them.")

    return Report(
        score=score,
        verdict=verdict,
        advice=ADVICE[verdict],
        top_reasons=top_reasons(by_category),
        by_category=by_category,
        category_points=category_points,
        auth=auth,
        notes=notes,
    )
