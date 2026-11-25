"""
Header analysis.

Looks at the "behind the scenes" part of an email (the headers) to answer:
1. Did the sending server pass SPF, DKIM, and DMARC checks?
2. Do the sender addresses line up, or do replies and bounces go somewhere else?

This file does NOT decide if an email is phishing. It only reports findings.
A later "risk scoring" step will weigh all findings together.
"""

import re

from detector.findings import Finding
from detector.suffixes import registrable_domain

# Matches pieces like "spf=fail" or "dkim=pass" inside Authentication-Results.
AUTH_PATTERN = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([a-z]+)", re.IGNORECASE)


# ---------- Helpers ----------

def domain_of(address):
    """'joe@mail.bank.example' -> 'mail.bank.example'"""
    if "@" not in address:
        return ""
    return address.rsplit("@", 1)[1].lower().strip(">. ")


def base_domain(domain):
    """
    'mail.bank.example' -> 'bank.example'
    'mail.bank.co.uk'   -> 'bank.co.uk'

    Uses the bundled Public Suffix List, so multi-part endings like 'co.uk'
    and shared hosts like 'github.io' are handled. See detector/suffixes.py.
    """
    return registrable_domain(domain)


def read_auth_results(auth_headers):
    """
    Pull SPF, DKIM, and DMARC results from the Authentication-Results headers.

    We only trust the FIRST (top) header. That one is added by the
    receiving mail server, the one you trust. Any headers further down
    could have been written by the attacker to look legit.
    """
    results = {"spf": "missing", "dkim": "missing", "dmarc": "missing"}
    if not auth_headers:
        return results

    for method, value in AUTH_PATTERN.findall(auth_headers[0]):
        method = method.lower()
        if results[method] == "missing":
            results[method] = value.lower()
    return results


# ---------- Main function ----------

def analyze_headers(email):
    """Takes a ParsedEmail. Returns (auth_results_dict, list_of_findings)."""
    findings = []
    auth = read_auth_results(email.auth_results)
    from_domain = domain_of(email.from_address)

    # --- SPF, DKIM, DMARC ---
    if all(v == "missing" for v in auth.values()):
        findings.append(Finding(
            "Authentication", "info",
            "No SPF/DKIM/DMARC results found. Can't judge either way. "
            "This is normal for some forwarded or hand-made email files."))
    else:
        dmarc = auth["dmarc"]
        if dmarc == "fail":
            findings.append(Finding(
                "DMARC", "high",
                f"DMARC failed. The email claims to be from '{from_domain}', "
                "but it did not pass that domain's own sender checks."))
        elif dmarc == "pass":
            findings.append(Finding(
                "DMARC", "info",
                f"DMARC passed. The email really came from a server allowed to send for '{from_domain}'. "
                "Note: this does NOT mean the domain itself is trustworthy."))
        elif dmarc in ("none", "missing"):
            findings.append(Finding(
                "DMARC", "low",
                "No DMARC result. The sending domain may not have DMARC set up."))

        spf = auth["spf"]
        if spf == "fail":
            findings.append(Finding(
                "SPF", "medium",
                "SPF failed. The sending server is not on the domain's list of allowed senders."))
        elif spf == "softfail":
            findings.append(Finding(
                "SPF", "low",
                "SPF soft-failed. The server is probably not allowed, but the domain isn't strict about it."))

        dkim = auth["dkim"]
        if dkim == "fail":
            findings.append(Finding(
                "DKIM", "medium",
                "DKIM failed. The digital signature doesn't match, so the email may have been changed."))
        elif dkim in ("none", "missing"):
            findings.append(Finding(
                "DKIM", "low",
                "No DKIM signature. The email isn't digitally signed."))

    # --- Do the addresses line up? ---
    if email.reply_to:
        reply_domain = domain_of(email.reply_to)
        if base_domain(reply_domain) != base_domain(from_domain):
            findings.append(Finding(
                "Reply-To", "medium",
                f"Replies go to '{reply_domain}', not the sender's domain '{from_domain}'. "
                "Scammers do this so your reply reaches them, not the real company."))

    if email.return_path:
        bounce_domain = domain_of(email.return_path)
        if base_domain(bounce_domain) != base_domain(from_domain):
            findings.append(Finding(
                "Return-Path", "low",
                f"Bounces go to '{bounce_domain}', not '{from_domain}'. "
                "Often harmless (mailing services do this), but worth noting."))

    # --- Basic structure ---
    if not email.message_id:
        findings.append(Finding(
            "Message-ID", "low",
            "No Message-ID. Almost every real mail server adds one."))

    return auth, findings
