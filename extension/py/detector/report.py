"""
Turn a Report into plain JSON-ready data.

Shared by the local server (server.py) and the Chrome extension's
built-in detector (which runs this same Python code inside Chrome).
Leaves out the email body on purpose.
"""

import json

from detector.parser import EmailParseError, parse_email
from detector.scoring import analyze_email


def report_to_dict(email, report):
    """Turn a Report into plain JSON. Leaves out the email body on purpose."""
    def finding(f):
        return {"check": f.check, "severity": f.severity, "message": f.message}

    return {
        "verdict": report.verdict,
        "score": report.score,
        "advice": report.advice,
        "email": {
            "from_name": email.from_name,
            "from_address": email.from_address,
            "subject": email.subject,
            "links": len(email.links),
            "attachments": len(email.attachments),
        },
        "auth": report.auth,
        "top_reasons": [finding(f) for f in report.top_reasons],
        "categories": [
            {"name": name, "points": report.category_points[name],
             "findings": [finding(f) for f in findings]}
            for name, findings in report.by_category.items()
        ],
        "notes": report.notes,
    }


def analyze_raw_to_json(raw):
    """
    Raw email (bytes or str) in, JSON text out. Used by the extension.
    Returns {"error": "..."} for input that isn't a valid email.
    """
    if isinstance(raw, str):
        raw = raw.encode("utf-8", errors="surrogateescape")
    try:
        email = parse_email(raw)
    except EmailParseError as err:
        return json.dumps({"error": str(err)})
    return json.dumps(report_to_dict(email, analyze_email(email)))
