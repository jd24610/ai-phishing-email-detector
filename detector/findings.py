"""
Shared data shape for results. Every check (headers, sender, URLs, AI)
reports what it found as a list of Finding objects.
"""

from dataclasses import dataclass

SEVERITIES = ("info", "low", "medium", "high")


@dataclass
class Finding:
    check: str      # which check produced this, e.g. "DMARC"
    severity: str   # "info", "low", "medium", or "high"
    message: str    # plain-English explanation
