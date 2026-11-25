"""
Public Suffix List lookup (offline).

A "public suffix" is the part of a domain anyone can register under:
'com', 'co.uk', 'github.io'. The "registrable domain" is one label more:
'bank.co.uk', 'someone.github.io'. That is the part a single owner controls,
so it's what we compare when asking "is this the same site?"

The list lives in detector/data/public_suffix_list.dat, a copy of
https://publicsuffix.org/list/public_suffix_list.dat (MPL 2.0). Nothing is
fetched at run time. To update it, download that file again over this one.

Both sections of the list are used. The "private" section has suffixes like
'github.io' where anyone can get a subdomain, so 'evil.github.io' and
'mybank.github.io' are correctly treated as different owners.

Matching follows the official algorithm (https://publicsuffix.org/list/):
- Normal rules match exactly: 'co.uk'.
- Wildcard rules match any one label: '*.ck' makes 'foo.ck' a suffix.
- Exception rules undo a wildcard: '!www.ck' makes 'www.ck' registrable.
- If nothing matches, the last label alone is the suffix (rule '*'). That is
  why reserved test domains like 'shop.example' still work.
"""

from functools import lru_cache
from pathlib import Path

LIST_PATH = Path(__file__).parent / "data" / "public_suffix_list.dat"
MAX_LIST_BYTES = 2_000_000  # the real list is ~350 KB; refuse anything absurd


def _to_ascii(rule):
    """The list has some rules in Unicode. Emails and URLs use 'xn--' form."""
    try:
        return rule.encode("idna").decode("ascii")
    except UnicodeError:
        return None


@lru_cache(maxsize=1)
def _load_rules():
    """Read the list once. Returns (normal, wildcard, exception) sets."""
    if LIST_PATH.stat().st_size > MAX_LIST_BYTES:
        raise ValueError("public_suffix_list.dat is larger than expected")

    normal, wildcard, exception = set(), set(), set()
    for line in LIST_PATH.read_text(encoding="utf-8").splitlines():
        rule = line.strip().lower()
        if not rule or rule.startswith("//"):
            continue
        rule = rule.split()[0]  # rules end at the first whitespace
        if rule.startswith("!"):
            target, rule = exception, rule[1:]
        elif rule.startswith("*."):
            target, rule = wildcard, rule[2:]
        else:
            target = normal
        target.add(rule)
        ascii_rule = _to_ascii(rule)
        if ascii_rule:
            target.add(ascii_rule)
    return normal, wildcard, exception


def _clean(domain):
    return ".".join(p for p in domain.lower().strip().strip(".").split(".") if p)


def public_suffix(domain):
    """'mail.bank.co.uk' -> 'co.uk'. Returns '' for an empty domain."""
    labels = _clean(domain).split(".")
    if labels == [""]:
        return ""
    normal, wildcard, exception = _load_rules()

    # Walk from the longest candidate to the shortest; first match is longest.
    for i in range(len(labels)):
        candidate = ".".join(labels[i:])
        if candidate in exception:
            return ".".join(labels[i + 1:])  # exception: drop its first label
        if candidate in normal:
            return candidate
        parent = ".".join(labels[i + 1:])
        if parent and parent in wildcard:
            return candidate
    return labels[-1]  # default rule '*'


def registrable_domain(domain):
    """
    'mail.bank.co.uk' -> 'bank.co.uk'
    'paypal.com.evil.example' -> 'evil.example'

    If the domain is itself a public suffix ('co.uk'), it is returned as-is,
    since there is nothing shorter to compare.
    """
    cleaned = _clean(domain)
    suffix = public_suffix(cleaned)
    if not suffix or cleaned == suffix:
        return cleaned
    owner = cleaned[: -len(suffix) - 1].rsplit(".", 1)[-1]
    return f"{owner}.{suffix}"
