"""
Sender analysis.

Header analysis tells us if an email really came from the domain it claims.
But a scammer can buy their own lookalike domain and pass every check.
This file asks a different question: does the sender LOOK like someone
they are not?

Checks:
1. Lookalike domains: "paypa1.com", "rnicrosoft.com", "amaz0n.com"
2. Brand names stuffed into fake domains: "paypal-security-alerts.com"
3. Punycode domains: letters from other alphabets that look identical
4. Display names that claim a brand the address doesn't belong to
5. Display names that hide a fake email address
6. "Official-sounding" names sent from free email accounts

Like headers.py, this only reports findings. It never gives a final verdict.
"""

import re

from detector.brands import FREE_PROVIDERS, KNOWN_BRANDS
from detector.findings import Finding
from detector.headers import base_domain, domain_of

# Characters scammers swap in because they look alike at a glance.
# Order matters: two-letter tricks first.
LOOKALIKE_SWAPS = [
    ("rn", "m"), ("vv", "w"), ("cl", "d"),
    ("0", "o"), ("1", "l"), ("3", "e"), ("5", "s"), ("4", "a"), ("7", "t"),
]

EMAIL_IN_TEXT = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
OFFICIAL_WORDS = re.compile(
    r"\b(support|security|team|bank|billing|account|service|helpdesk|admin|it|payroll|hr|"
    r"ceo|cfo|president|director|finance)\b",
    re.IGNORECASE)


# ---------- Helpers ----------

def undo_lookalikes(text):
    """'paypa1' -> 'paypal', 'rnicrosoft' -> 'microsoft'"""
    text = text.lower()
    for fake, real in LOOKALIKE_SWAPS:
        text = text.replace(fake, real)
    return text


def edit_distance(a, b):
    """
    How many single-letter edits (add, remove, change) turn a into b.
    'amazom' vs 'amazon' = 1. Classic dynamic programming.
    """
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i]
        for j, cb in enumerate(b, 1):
            curr.append(min(prev[j] + 1,               # remove a letter
                            curr[j - 1] + 1,           # add a letter
                            prev[j - 1] + (ca != cb))) # change a letter
        prev = curr
    return prev[-1]


def is_official(domain):
    """True if the domain (or a subdomain of it) belongs to a known brand."""
    base = base_domain(domain)
    return any(base in domains for domains in KNOWN_BRANDS.values())


def brand_in_name(display_name):
    """Return the brand mentioned in a display name, if any (whole words only)."""
    for brand in KNOWN_BRANDS:
        if re.search(rf"\b{re.escape(brand)}\b", display_name, re.IGNORECASE):
            return brand
    return None


# ---------- Domain checks ----------

def check_domain(domain, role):
    """Check one domain (From or Reply-To) for lookalike tricks."""
    findings = []
    if not domain:
        return findings

    # Punycode: domains with non-English letters are stored as "xn--..."
    # A Cyrillic "а" looks exactly like an English "a" on screen.
    if any(part.startswith("xn--") for part in domain.split(".")):
        findings.append(Finding(
            f"{role} domain", "high",
            f"'{domain}' uses special characters (punycode). This can hide letters "
            "from other alphabets that look identical to normal ones."))

    if is_official(domain):
        return findings  # it's the real brand domain, nothing more to check

    label = base_domain(domain).split(".")[0]        # "paypa1" from "paypa1.com"
    squashed = label.replace("-", "")                 # "paypalsecurity" from "paypal-security"
    words = re.split(r"[-.]", domain.lower())         # ["mail", "paypal", "security", "com"]

    for brand, real_domains in KNOWN_BRANDS.items():
        real_label = real_domains[0].split(".")[0]    # "paypal" from "paypal.com"

        if undo_lookalikes(label) == real_label and label != real_label:
            findings.append(Finding(
                f"{role} domain", "high",
                f"'{domain}' swaps look-alike characters to imitate {real_domains[0]}."))
            break

        if len(real_label) >= 5:
            allowed = 1 if len(real_label) < 8 else 2
            if 0 < edit_distance(label, real_label) <= allowed:
                findings.append(Finding(
                    f"{role} domain", "medium",
                    f"'{domain}' is only a letter or two off from {real_domains[0]}. "
                    "Could be a typo-squat, or could be a real but unrelated site."))
                break
            if real_label in squashed:
                findings.append(Finding(
                    f"{role} domain", "medium",
                    f"'{domain}' contains the brand name '{real_label}' but is not "
                    f"an official {brand.title()} domain."))
                break
        elif real_label in words:
            # Short names like "ups" must match a whole word,
            # otherwise "groups.com" would be flagged.
            findings.append(Finding(
                f"{role} domain", "medium",
                f"'{domain}' contains the brand name '{real_label}' but is not "
                f"an official {brand.upper()} domain."))
            break

    return findings


# ---------- Display name checks ----------

def check_display_name(display_name, address):
    findings = []
    if not display_name:
        return findings

    domain = domain_of(address)
    base = base_domain(domain)

    # A display name like "support@paypal.com" hides the real address.
    for hidden in EMAIL_IN_TEXT.findall(display_name):
        if hidden.lower() != address:
            findings.append(Finding(
                "Display name", "high",
                f"The name shows '{hidden}' but the real address is '{address}'. "
                "Many phones only show the name, so this hides the real sender."))

    brand = brand_in_name(display_name)
    if brand and base not in KNOWN_BRANDS[brand]:
        findings.append(Finding(
            "Display name", "high",
            f"The name says '{display_name}', but the email comes from '{domain}', "
            f"which is not an official {brand.title()} domain."))

    if base in FREE_PROVIDERS and (brand or OFFICIAL_WORDS.search(display_name)):
        findings.append(Finding(
            "Free email", "medium",
            f"'{display_name}' sounds official, but it was sent from a free "
            f"{base} account. Real companies use their own domain."))

    return findings


# ---------- Main function ----------

def analyze_sender(email):
    """Takes a ParsedEmail. Returns a list of findings."""
    findings = []
    findings += check_display_name(email.from_name, email.from_address)
    findings += check_domain(domain_of(email.from_address), "From")
    if email.reply_to:
        findings += check_domain(domain_of(email.reply_to), "Reply-To")
    return findings
