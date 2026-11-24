"""
Brands that phishers love to pretend to be, and their REAL domains.

To protect a new brand, add one line. Keys are how the name appears
in a display name. Values are the official domains that brand sends from.
"""

KNOWN_BRANDS = {
    "paypal": ["paypal.com"],
    "apple": ["apple.com"],
    "microsoft": ["microsoft.com", "office.com", "microsoftonline.com"],
    "google": ["google.com"],
    "amazon": ["amazon.com"],
    "netflix": ["netflix.com"],
    "chase": ["chase.com"],
    "bank of america": ["bankofamerica.com", "bofa.com"],
    "wells fargo": ["wellsfargo.com"],
    "docusign": ["docusign.com", "docusign.net"],
    "fedex": ["fedex.com"],
    "dhl": ["dhl.com"],
    "ups": ["ups.com"],
    "usps": ["usps.com"],
    "irs": ["irs.gov"],
    # Fictional brand used by our test samples. Safe to leave in.
    "northbridge bank": ["northbridgebank.example"],
}

# Free email services. Real companies don't send official mail from these.
FREE_PROVIDERS = {
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "live.com",
    "aol.com", "icloud.com", "proton.me", "protonmail.com", "gmx.com",
    "mail.com", "yandex.com",
    "freemail.example",  # fictional, used in test samples
}
