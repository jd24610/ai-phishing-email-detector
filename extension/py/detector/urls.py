"""
URL analysis (offline part).

Most phishing emails want one thing: for you to click a link.
This file looks at every link and asks: is this link lying to you?

IMPORTANT: we never visit, open, or download any link here.
Everything is done by reading the link as plain text.
Checking links against online blocklists (Safe Browsing, VirusTotal)
comes later, and even then we only send the link text, never open it.

Checks:
1. Text says one site, link goes to another
2. Links to raw IP addresses instead of a domain name
3. The "@" trick: http://paypal.com@evil.com really goes to evil.com
4. A real brand domain used as a fake subdomain: paypal.com.evil.com
5. Dangerous link types: javascript:, data:, file:
6. Link shorteners that hide the real destination
7. Lookalike domains (reuses the sender checks)
8. Plain http (no encryption)
"""

import ipaddress
import re
from urllib.parse import urlsplit

from detector.brands import KNOWN_BRANDS
from detector.findings import Finding
from detector.headers import base_domain
from detector.sender import check_domain, is_official

MAX_LINKS = 100  # stop a giant email with thousands of links from slowing us down

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy", "t.ly",
}

DANGEROUS_SCHEMES = {"javascript", "data", "file", "vbscript"}

# Finds something shaped like a domain in normal text: "www.bank.com"
DOMAIN_IN_TEXT = re.compile(r"(?:[a-z0-9-]+\.)+[a-z]{2,}", re.IGNORECASE)


def defang(url):
    """
    Make a link unclickable before showing it.
    "https://bad.com" becomes "hxxps://bad[.]com".
    """
    return url.replace("http", "hxxp", 1).replace(".", "[.]")


def _is_ip(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _domain_shown(display_text):
    """Pull the domain out of what the reader sees, if it looks like a web address."""
    text = display_text.strip().lower()
    if text.startswith(("http://", "https://")):
        try:
            return urlsplit(text).hostname or ""
        except ValueError:
            return ""
    match = DOMAIN_IN_TEXT.search(text)
    return match.group(0) if match else ""


def check_link(link):
    """Check one Link from the parser. Returns a list of findings."""
    findings = []
    url = link.url.strip()
    safe = defang(url)

    if not url or url.startswith("#"):
        return findings  # jump-to-section link inside the email, harmless

    try:
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
    except ValueError:
        return [Finding("Link", "low", f"Broken or unreadable link: {safe}")]

    scheme = parts.scheme.lower()

    # 5. Dangerous link types
    if scheme in DANGEROUS_SCHEMES:
        return [Finding("Link", "high",
                        f"Link uses '{scheme}:', which can run code or hide content. "
                        "Real emails don't use these.")]
    if scheme == "mailto" or scheme not in ("http", "https"):
        return findings  # email links and other non-web links are out of scope here

    # 3. The "@" trick. Everything before @ is ignored by the browser.
    if parts.username:
        findings.append(Finding(
            "Link", "high",
            f"Link uses the '@' trick: it looks like it starts with '{parts.username}', "
            f"but really goes to '{host}'. Link: {safe}"))

    # 2. Raw IP address
    if _is_ip(host):
        findings.append(Finding(
            "Link", "high",
            f"Link goes to a raw IP address ({host}) instead of a website name. "
            f"Real companies almost never do this. Link: {safe}"))

    # 1. Text says one thing, link goes somewhere else
    shown = _domain_shown(link.display_text)
    if shown and host and base_domain(shown) != base_domain(host):
        findings.append(Finding(
            "Link", "high",
            f"Link text shows '{shown}' but really goes to '{host}'. "
            "This is one of the most common phishing tricks."))

    if host and not _is_ip(host):
        # 4. Real brand domain hiding as a subdomain
        if not is_official(host):
            for real_domains in KNOWN_BRANDS.values():
                for real in real_domains:
                    if f"{real}." in host:
                        findings.append(Finding(
                            "Link", "high",
                            f"'{host}' starts with '{real}' but really belongs to "
                            f"'{base_domain(host)}'. The real domain is always at the end."))

        # 6. Shorteners
        if base_domain(host) in SHORTENERS:
            findings.append(Finding(
                "Link", "medium",
                f"Link uses a shortener ({host}), which hides the real destination. "
                "We don't follow it, because that would mean visiting the link."))

        # 7. Lookalike domains, same checks we use on the sender
        findings += check_domain(host, "Link")

    # 8. No encryption
    if scheme == "http":
        findings.append(Finding(
            "Link", "low",
            f"Link uses plain http (not encrypted). Weak signal on its own: "
            f"many phishing sites use https too. Link: {safe}"))

    return findings


def analyze_urls(email):
    """Takes a ParsedEmail. Returns a list of findings for all its links."""
    findings = []
    links = email.links[:MAX_LINKS]
    for link in links:
        findings += check_link(link)
    if len(email.links) > MAX_LINKS:
        findings.append(Finding(
            "Link", "low",
            f"Email has {len(email.links)} links. Only the first {MAX_LINKS} were checked."))
    return findings
