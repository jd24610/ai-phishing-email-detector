"""
Wording analysis (rules layer).

Some scams have no bad links, no attachments, and a clean sender:
    "Hi, it's your boss. Buy 5 gift cards and keep this between us."
The only clue is the WORDING. This file looks for the pressure tactics
scammers use: urgency, threats, secrecy, and requests for money or passwords.

How it works: lists of phrase patterns (regular expressions), grouped by tactic.
Everything runs offline. No email text leaves the machine.

LIMITATION: rules only catch phrasings we thought of. A scammer who writes
"pick up some Apple store credit" instead of "gift cards" can slip past.
That's why a trained model and an AI layer come later.
"""

import html
import re

from detector.findings import Finding

MAX_TEXT = 50_000  # only scan the first 50k characters, keeps it fast on huge emails

# Invisible characters scammers insert to break up words like "gi​ft card",
# so keyword filters miss them while the reader sees nothing odd.
INVISIBLE = re.compile("[​‌‍⁠﻿­]")

# Each tactic: (name, severity, explanation, [patterns])
TACTICS = [
    ("Money request", "high",
     "Asks for gift cards, wire transfers, or crypto. These are hard to trace and "
     "almost impossible to get back, which is why scammers want them.",
     [r"gift\s?cards?", r"(google play|itunes|apple|amazon|steam)\s+cards?",
      r"wire\s+(transfer|the money|the funds)", r"western union", r"moneygram",
      r"bitcoin|crypto(currency)?|btc wallet",
      r"(send|scratch).{0,40}(codes?|card numbers?)"]),

    ("Credential request", "medium",
     "Asks you to verify, confirm, or enter login or personal details. Real companies "
     "rarely ask for this by email.",
     [r"(verify|confirm|validate|update)\s+your\s+(account|identity|password|login|"
      r"credentials|payment|billing|information|details)",
      r"enter\s+your\s+(password|pin|login|credentials)",
      r"log\s?in\s+to\s+(restore|unlock|reactivate|keep)",
      r"social security( number)?|\bssn\b"]),

    ("Threat", "medium",
     "Threatens a bad outcome (account closed, legal action) to scare you into acting fast.",
     [r"(account|access|card|service).{0,30}(suspended|locked|closed|terminated|"
      r"disabled|deactivated|on hold)",
      r"legal action|lawsuit|arrest|warrant|penalt(y|ies)",
      r"unauthori[sz]ed (activity|access|transaction|login)",
      r"(permanently|will be) (deleted|closed|lost)"]),

    ("Secrecy", "medium",
     "Asks you to keep it quiet or says they can't talk. Scammers isolate you so "
     "nobody stops the scam.",
     [r"keep (this|it) (between us|confidential|quiet|private|to yourself)",
      r"(don'?t|do not) (tell|mention|discuss|share)",
      r"(i'?m|i am) in a meeting",
      r"(can'?t|cannot|unable to) (talk|take calls|call)",
      r"it'?s a surprise"]),

    ("Payment change", "medium",
     "Says bank or payment details have changed. This is a common invoice scam: "
     "the money goes to the scammer's account instead.",
     [r"(new|updated|changed?)\s+(bank(ing)?|account|payment|wire)\s+(details|information|"
      r"instructions)",
      r"(change|update)\s+(of|to|in)\s+(bank|banking|payment)"]),

    ("Too good to be true", "medium",
     "Promises a prize, refund, or money you weren't expecting.",
     [r"you('?ve| have) (won|been selected)", r"claim your (prize|reward|refund|gift)",
      r"lottery|inheritance|unclaimed (funds|money)"]),

    ("Urgency", "low",
     "Pushes you to act fast so you don't stop and think. Weak on its own, "
     "since sales emails do this too.",
     [r"\burgent(ly)?\b", r"\bimmediately\b", r"\basap\b", r"right away",
      r"within \d+ (hours?|minutes?)", r"act now", r"final (notice|warning|reminder)",
      r"expires? today", r"as soon as possible", r"\bquickly\b"]),

    ("Generic greeting", "low",
     "Uses a generic greeting instead of your name. Companies you do business "
     "with usually know your name.",
     [r"^\s*dear (customer|user|client|member|valued customer|account holder|sir|madam)"]),
]

COMPILED = [(name, sev, why, [re.compile(p, re.IGNORECASE | re.MULTILINE) for p in pats])
            for name, sev, why, pats in TACTICS]


def visible_text(email):
    """Subject + body as plain lowercase text, with HTML tags and tricks removed."""
    body = email.text_body
    if not body.strip() and email.html_body:
        body = re.sub(r"<(script|style)[^>]*>.*?</\1>", " ", email.html_body,
                      flags=re.IGNORECASE | re.DOTALL)
        body = html.unescape(re.sub(r"<[^>]+>", " ", body))

    text = f"{email.subject}\n{body}"[:MAX_TEXT]
    text = INVISIBLE.sub("", text)
    text = text.replace("’", "'").replace("‘", "'")  # curly apostrophes
    return text.lower()


def analyze_language(email):
    """Takes a ParsedEmail. Returns a list of findings about its wording."""
    text = visible_text(email)
    findings = []
    found = set()

    for name, severity, why, patterns in COMPILED:
        phrases = []
        for pattern in patterns:
            match = pattern.search(text)
            if match:
                phrases.append(" ".join(match.group(0).split()))
        if phrases:
            found.add(name)
            quoted = ", ".join(f"'{p}'" for p in phrases[:3])
            findings.append(Finding(name, severity, f"{why} Found: {quoted}."))

    # Some tactics together are much worse than either alone.
    if "Money request" in found and ("Secrecy" in found or "Urgency" in found):
        findings.append(Finding(
            "Scam pattern", "high",
            "Asks for money or gift cards AND pushes secrecy or speed. This is the classic "
            "'boss needs gift cards' scam (also called CEO fraud or BEC)."))
    if "Credential request" in found and "Threat" in found:
        findings.append(Finding(
            "Scam pattern", "medium",
            "Threatens your account AND asks you to verify your details. This is the "
            "classic 'account suspended, log in to fix it' phishing pattern."))

    return findings
