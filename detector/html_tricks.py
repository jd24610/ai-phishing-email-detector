"""
HTML trick checks.

An HTML email can look completely different from what's actually in it.
Scammers use that in two ways:

1. Login forms inside the email. The email itself asks you to type your
   password or card number, then sends it straight to the scammer when you
   press the button. No link to check, no fake website to block.
2. Hidden text. Text the reader can't see, but that spam filters and other
   tools still read:
   - Large blocks of hidden text stuffed in to make the email look harmless
     to filters ("hash busting" / filter poisoning).
   - Hidden characters spliced inside words, so "PayPal" on screen is
     "PayXPal" to a keyword filter.

What counts as hidden: display:none, visibility:hidden, opacity:0,
font-size:0 or 1px, zero height with overflow hidden, the HTML 'hidden'
attribute, and text the same color as its background (white on white).

IMPORTANT: a small amount of hidden text is normal. Many real newsletters
hide a one-line "preview" (a preheader) that only shows in the inbox list.
So hidden text alone is not flagged. Only large amounts, or hidden
characters inside words, are.

Like every other check, this only READS the HTML. Nothing is rendered,
no images or styles are loaded, and form actions are never visited.
"""

import re
from collections import Counter
from html.parser import HTMLParser
from urllib.parse import urlsplit

from detector.findings import Finding

MAX_HTML = 1_000_000          # only scan the first 1M characters of HTML
HIDDEN_TEXT_LIMIT = 300       # more hidden characters than this is suspicious
PREVIEW_CHARS = 60            # how much hidden text to quote in a finding
MAX_DEPTH = 500               # deeper nesting than this is ignored (broken or hostile HTML)

# Elements with no closing tag. They never wrap text.
VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link",
        "meta", "param", "source", "track", "wbr"}

# Tags that start a new line, so text on either side isn't the same word.
BLOCK = {"address", "article", "aside", "blockquote", "br", "dd", "div", "dl",
         "dt", "footer", "form", "h1", "h2", "h3", "h4", "h5", "h6", "header",
         "hr", "li", "main", "nav", "ol", "p", "pre", "section", "table",
         "tbody", "td", "tfoot", "th", "thead", "tr", "ul"}

# Text inside these is never shown, so it doesn't count as "hidden text".
NOT_TEXT = {"script", "style", "head", "title", "template", "noscript"}

# Input names that ask for something nobody should type into an email.
SENSITIVE_FIELD = re.compile(
    r"pass|pwd|(?<![a-z])pin(?![a-z])|cvv|cvc|card|ccnum|(?<![a-z])ssn|social.?sec|"
    r"routing|account.?num|iban|(?<![a-z])otp(?![a-z])|2fa|security.?code|login|username",
    re.IGNORECASE)

# Zero-width characters used as padding in preheaders. Not real text.
ZERO_WIDTH = re.compile(r"[\u200b\u200c\u200d\u2060\ufeff\u00ad\u034f\s]")

NAMED_COLORS = {"white": "#ffffff", "black": "#000000"}


# ---------- Small CSS helpers ----------

def _style(attrs):
    """'color: red; FONT-SIZE:0 !important' -> {'color': 'red', 'font-size': '0'}"""
    out = {}
    for part in (attrs.get("style") or "").split(";"):
        if ":" in part:
            prop, value = part.split(":", 1)
            value = value.lower().replace("!important", "").strip()
            out[prop.strip().lower()] = value
    return out


def _number(value):
    """'0px' -> 0.0, '1.5pt' -> 1.5, 'auto' -> None"""
    match = re.match(r"\s*(-?\d*\.?\d+)", value or "")
    return float(match.group(1)) if match else None


def _color(value):
    """Normalize a CSS color so 'white', '#FFF' and 'rgb(255,255,255)' compare equal."""
    if not value:
        return None
    v = value.strip().lower()
    v = NAMED_COLORS.get(v, v)
    if re.fullmatch(r"#[0-9a-f]{3}", v):
        v = "#" + "".join(c * 2 for c in v[1:])
    rgb = re.fullmatch(r"rgba?\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*(?:,\s*([\d.]+)\s*)?\)", v)
    if rgb:
        if rgb.group(4) is not None and float(rgb.group(4)) == 0:
            return "transparent"
        v = "#" + "".join(f"{min(int(x), 255):02x}" for x in rgb.groups()[:3])
    return v


def _background(style, attrs):
    """The background color an element sets, if any."""
    bg = style.get("background-color") or attrs.get("bgcolor")
    if not bg and "background" in style:
        # 'background: #fff url(x.png) no-repeat' -> take the color part
        for word in style["background"].split():
            if _color(word) and (word.startswith("#") or word.startswith("rgb")
                                 or word in NAMED_COLORS):
                bg = word
                break
    color = _color(bg)
    return None if color == "transparent" else color


def _hidden_reason(tag, style, attrs):
    """Why this element hides its content, or '' if it doesn't."""
    if "hidden" in attrs:
        return "the 'hidden' attribute"
    if style.get("display") == "none":
        return "display:none"
    if style.get("visibility") in ("hidden", "collapse"):
        return "visibility:hidden"
    opacity = _number(style.get("opacity"))
    if opacity is not None and opacity <= 0.05:
        return "opacity:0"
    size = _number(style.get("font-size"))
    if size is not None and size <= 1:
        return f"font-size:{style['font-size']}"
    if tag == "font" and _number(attrs.get("size")) == 0:
        return "font size 0"
    if style.get("overflow") == "hidden":
        for prop in ("max-height", "height", "max-width", "width"):
            if _number(style.get(prop)) == 0:
                return f"{prop}:0 with overflow:hidden"
    return ""


# ---------- The HTML walker ----------

class _Walker(HTMLParser):
    """
    Walks the HTML once, keeping a stack of open elements so it knows,
    for every piece of text, whether a parent hides it and what color it is.
    """

    def __init__(self):
        super().__init__(convert_charrefs=True)
        # Each entry: (tag, hidden_reason, text_color, background_color)
        self.stack = [("root", "", "#000000", "#ffffff")]
        self.open_tags = Counter()   # how many of each tag are open, for fast lookups
        self.segments = []   # (text, hidden_reason) in reading order
        self.forms = []      # {"action": str, "fields": [(type, name)]}
        self.loose_fields = []  # inputs outside any <form>
        self.form_depth = 0

    # -- state of the element we're inside --
    def _top(self):
        return self.stack[-1]

    def _skip_text(self):
        return any(self.open_tags[tag] for tag in NOT_TEXT)

    def handle_starttag(self, tag, attr_list):
        attrs = {k.lower(): (v or "") for k, v in attr_list}
        style = _style(attrs)

        if tag in BLOCK:
            self.segments.append(("\n", ""))

        # Forms and fields
        if tag == "form":
            self.forms.append({"action": attrs.get("action", "").strip(), "fields": []})
            self.form_depth += 1
        if tag in ("input", "textarea", "select"):
            kind = attrs.get("type", "text").lower() if tag == "input" else tag
            if kind not in ("hidden", "submit", "button", "image", "reset"):
                field = (kind, attrs.get("name", "") or attrs.get("id", "")
                         or attrs.get("placeholder", ""))
                if self.form_depth and self.forms:
                    self.forms[-1]["fields"].append(field)
                else:
                    self.loose_fields.append(field)

        if tag in VOID or len(self.stack) >= MAX_DEPTH:
            return

        _, parent_hidden, parent_color, parent_bg = self._top()
        own_color = _color(style.get("color") or (attrs.get("color") if tag == "font" else ""))
        own_bg = _background(style, attrs)
        color = own_color or parent_color
        bg = own_bg or parent_bg

        hidden = parent_hidden or _hidden_reason(tag, style, attrs)
        if not hidden and (own_color or own_bg) and color == bg:
            # This element set its text color to match the background (or the
            # other way round), e.g. white text on a white email.
            hidden = "text the same color as its background"
        self.stack.append((tag, hidden, color, bg))
        self.open_tags[tag] += 1

    def handle_startendtag(self, tag, attr_list):
        self.handle_starttag(tag, attr_list)
        if tag not in VOID:
            self.handle_endtag(tag)

    def handle_endtag(self, tag):
        if tag in BLOCK:
            self.segments.append(("\n", ""))
        if tag == "form" and self.form_depth:
            self.form_depth -= 1
        # Close the matching element. Broken HTML often skips closing tags,
        # so pop back to the nearest match, and ignore strays with no match.
        if not self.open_tags[tag]:
            return
        for i in range(len(self.stack) - 1, 0, -1):
            if self.stack[i][0] == tag:
                for closed, *_ in self.stack[i:]:
                    self.open_tags[closed] -= 1
                del self.stack[i:]
                break

    def handle_data(self, data):
        if data and not self._skip_text():
            self.segments.append((data, self._top()[1]))


# ---------- Checks ----------

def _preview(text):
    text = " ".join(ZERO_WIDTH.sub(" ", text).split())
    return text if len(text) <= PREVIEW_CHARS else text[:PREVIEW_CHARS] + "..."


def _words_split(segments):
    """
    Hidden text placed in the middle of a word: visible letters right
    before it and right after it, with no space in between.
    Returns a list of (before, hidden, after) examples.
    """
    # One pass each way to find the nearest visible text before and after
    # every segment. (Searching from scratch for each one is far too slow
    # on a big email full of hidden pieces.)
    n = len(segments)
    prev_visible, next_visible = [""] * n, [""] * n
    last = ""
    for i, (text, hidden) in enumerate(segments):
        prev_visible[i] = last
        if not hidden:
            last = text
    last = ""
    for i in range(n - 1, -1, -1):
        next_visible[i] = last
        if not segments[i][1]:
            last = segments[i][0]

    examples = []
    for i, (text, hidden) in enumerate(segments):
        if not hidden or not ZERO_WIDTH.sub("", text):
            continue
        before, after = prev_visible[i], next_visible[i]
        if (before and after and before[-1].isalnum() and after[0].isalnum()
                and not text[0].isspace() and not text[-1].isspace()):
            word_start = re.search(r"\w+$", before).group(0)
            word_end = re.match(r"\w+", after).group(0)
            examples.append((word_start, text.strip(), word_end))
    return examples


def _form_findings(walker):
    findings = []
    for form in walker.forms:
        fields = form["fields"]
        if not fields:
            continue
        sensitive = [name or kind for kind, name in fields
                     if kind == "password" or SENSITIVE_FIELD.search(name)]
        action = form["action"]
        host = ""
        if action.lower().startswith(("http://", "https://")):
            try:
                host = (urlsplit(action).hostname or "").lower()
            except ValueError:
                host = ""
        where = f" Pressing the button sends what you type to '{host}'." if host else ""

        if sensitive:
            quoted = [f"'{s}'" for s in sensitive[:3]]
            asked = quoted[0] if len(quoted) == 1 else ", ".join(quoted[:-1]) + " and " + quoted[-1]
            findings.append(Finding(
                "Login form", "high",
                f"The email contains a form asking for {asked}.{where} Real companies "
                "never ask you to type a password or card number into an email."))
        else:
            findings.append(Finding(
                "Form", "medium",
                f"The email contains a form with {len(fields)} field(s) to type into.{where} "
                "Forms inside emails are rare and are often used to collect personal details."))

    already_flagged = any(f.check == "Login form" for f in findings)
    if not already_flagged:
        if any(kind == "password" or SENSITIVE_FIELD.search(name)
               for kind, name in walker.loose_fields):
            findings.append(Finding(
                "Login form", "high",
                "The email contains a password or card number box. Real companies never "
                "ask you to type these into an email."))
    return findings


def _hidden_findings(walker):
    findings = []
    segments = walker.segments

    split = _words_split(segments)
    if split:
        start, hidden, end = split[0]
        places = "1 place" if len(split) == 1 else f"{len(split)} places"
        findings.append(Finding(
            "Hidden text", "medium",
            f"Hidden characters are placed inside words ({places}). For example "
            f"'{start}{end}' on screen is really '{start}{_preview(hidden)}{end}'. "
            "This hides words like brand names from spam filters."))

    hidden_parts = [(t, h) for t, h in segments if h and ZERO_WIDTH.sub("", t)]
    hidden_chars = sum(len(ZERO_WIDTH.sub("", t)) for t, _ in hidden_parts)
    if hidden_chars > HIDDEN_TEXT_LIMIT:
        reasons = sorted({h for _, h in hidden_parts})
        sample = _preview(" ".join(t for t, _ in hidden_parts))
        findings.append(Finding(
            "Hidden text", "medium",
            f"The email has {hidden_chars} characters of text you can't see "
            f"(hidden with {', '.join(reasons[:3])}). Scammers stuff in hidden text to "
            f"make an email look harmless to spam filters. Starts with: '{sample}'"))
    elif hidden_chars:
        findings.append(Finding(
            "Hidden text", "info",
            f"A little hidden text ({hidden_chars} characters). This is usually the inbox "
            "preview line that many real newsletters use."))
    return findings


def analyze_html(email):
    """Takes a ParsedEmail. Returns a list of findings about tricks in its HTML."""
    html_body = email.html_body or ""
    if not html_body.strip():
        return []

    walker = _Walker()
    try:
        walker.feed(html_body[:MAX_HTML])
        walker.close()
    except Exception:
        pass  # badly broken HTML: report what we managed to read

    return _form_findings(walker) + _hidden_findings(walker)
