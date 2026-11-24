"""
Email parser.

Takes a raw email file (.eml) and turns it into clean, organized data
that the other checks (headers, sender, URLs, AI) can work with.

Safety rules this file follows:
- It only READS the email. It never opens links.
- It never saves or runs attachments. It only measures and fingerprints them.
- It refuses files that are too big or don't look like an email.
"""

import hashlib
import io
import re
import zipfile
from dataclasses import dataclass, field
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from html.parser import HTMLParser

# Real emails are rarely bigger than this. A size limit stops someone
# from crashing the tool with a giant file.
MAX_EMAIL_SIZE = 10 * 1024 * 1024  # 10 MB

# Finds web links in plain text, like "https://example.com/page".
URL_PATTERN = re.compile(r"https?://[^\s<>\"')\]]+", re.IGNORECASE)

# A zip listing thousands of files is either a "zip bomb" or abuse. Stop there.
MAX_ARCHIVE_MEMBERS = 500


# ---------- Data shapes ----------
# These "dataclasses" are just labeled boxes for the data we pull out.

@dataclass
class Link:
    url: str                 # where the link really goes
    display_text: str = ""   # what the reader sees (HTML links only)
    source: str = "text"     # "html" or "text"


@dataclass
class Attachment:
    filename: str
    content_type: str
    size_bytes: int
    sha256: str  # a fingerprint of the file, used later for VirusTotal lookups
    # The first few bytes reveal the REAL file type, no matter what the name says.
    # Reading bytes is safe. We never save or run the file.
    first_bytes: bytes = b""
    # For ZIP-based files: the names of the files inside. We read the zip's
    # table of contents only. Nothing is unzipped, saved, or run.
    archive_members: list = field(default_factory=list)
    archive_encrypted: bool = False   # password-protected, so contents can't be checked
    archive_error: str = ""           # set if the zip is broken or too big to list


@dataclass
class ParsedEmail:
    from_name: str
    from_address: str
    reply_to: str
    return_path: str
    to: str
    subject: str
    date: str
    message_id: str
    received_chain: list = field(default_factory=list)  # the servers it passed through
    auth_results: list = field(default_factory=list)    # SPF / DKIM / DMARC results
    text_body: str = ""
    html_body: str = ""
    links: list = field(default_factory=list)
    attachments: list = field(default_factory=list)


class EmailParseError(Exception):
    """Raised when the input can't be treated as a valid email."""


# ---------- Link finder for HTML ----------

class _LinkCollector(HTMLParser):
    """
    Walks through HTML and records every <a href="..."> link,
    along with the text the reader actually sees.

    This matters because phishing emails often show one address
    ("www.yourbank.com") but link to a different one.
    """

    def __init__(self):
        super().__init__()
        self.links = []
        self._href = None
        self._text = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            href = dict(attrs).get("href")
            if href:
                self._href = href.strip()
                self._text = []

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            visible = " ".join("".join(self._text).split())
            self.links.append(Link(url=self._href, display_text=visible, source="html"))
            self._href = None


# ---------- Helpers ----------

def _header(msg, name):
    """Read one header safely. Broken headers return an empty string instead of crashing."""
    try:
        value = msg.get(name)
        return str(value).strip() if value is not None else ""
    except Exception:
        return ""


def _all_headers(msg, name):
    """Some headers appear many times (like Received). Get all of them."""
    try:
        return [str(v).strip() for v in (msg.get_all(name) or [])]
    except Exception:
        return []


def _part_text(part):
    """
    Get the text out of one part of the email.
    Spammers often use broken character sets, so if the normal way fails
    we fall back to a forgiving decode instead of crashing.
    """
    try:
        return part.get_content()
    except Exception:
        raw = part.get_payload(decode=True) or b""
        return raw.decode("utf-8", errors="replace")


def _list_zip(data):
    """
    Read a zip's table of contents WITHOUT unzipping anything.

    Why this is safe: a zip file keeps a list of its contents at the end
    (the "central directory"). We only read that list. We never decompress,
    so a "zip bomb" (a tiny file that unzips to terabytes) can't hurt us.

    Returns (names, encrypted, error).
    """
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            infos = zf.infolist()
            if len(infos) > MAX_ARCHIVE_MEMBERS:
                return [], False, f"Archive lists {len(infos)} files, over the {MAX_ARCHIVE_MEMBERS} limit."
            names = [i.filename for i in infos if not i.is_dir()]
            encrypted = any(i.flag_bits & 0x1 for i in infos)  # bit 1 = password-protected
            return names, encrypted, ""
    except (zipfile.BadZipFile, ValueError, OSError, RuntimeError) as err:
        return [], False, f"Could not read archive: {type(err).__name__}"


def _extract_links(text_body, html_body):
    links = []
    seen = set()

    if html_body:
        collector = _LinkCollector()
        try:
            collector.feed(html_body)
        except Exception:
            pass  # badly broken HTML: keep whatever links we found
        for link in collector.links:
            if link.url not in seen:
                seen.add(link.url)
                links.append(link)

    for match in URL_PATTERN.findall(text_body or ""):
        url = match.rstrip(".,;:!?")
        if url not in seen:
            seen.add(url)
            links.append(Link(url=url, source="text"))

    return links


# ---------- Main function ----------

def parse_email(raw_bytes):
    """Turn raw email bytes into a ParsedEmail. Raises EmailParseError on bad input."""

    # 1. Validate the input before doing anything with it.
    if not isinstance(raw_bytes, (bytes, bytearray)):
        raise EmailParseError("Input must be raw bytes from an .eml file.")
    if len(raw_bytes) == 0:
        raise EmailParseError("The file is empty.")
    if len(raw_bytes) > MAX_EMAIL_SIZE:
        raise EmailParseError("The file is larger than the 10 MB limit.")

    # 2. Let Python's built-in email library split the message into parts.
    msg = BytesParser(policy=policy.default).parsebytes(bytes(raw_bytes))

    # Every real email has a From header. If it's missing, this isn't an email.
    from_raw = _header(msg, "From")
    if not from_raw:
        raise EmailParseError("No 'From' header found. This doesn't look like an email.")

    from_name, from_address = parseaddr(from_raw)

    # 3. Walk through every part: plain text, HTML, and attachments.
    text_parts, html_parts, attachments = [], [], []

    for part in msg.walk():
        if part.is_multipart():
            continue  # this is just a container, the real content is inside

        filename = part.get_filename()
        disposition = part.get_content_disposition()
        content_type = part.get_content_type()

        if disposition == "attachment" or filename:
            # We fingerprint the attachment but NEVER save or open it.
            data = part.get_payload(decode=True) or b""
            members, encrypted, archive_error = [], False, ""
            if data.startswith(b"PK\x03\x04"):  # ZIP signature (also .docx/.xlsx)
                members, encrypted, archive_error = _list_zip(data)
            attachments.append(Attachment(
                filename=filename or "(no name)",
                content_type=content_type,
                size_bytes=len(data),
                sha256=hashlib.sha256(data).hexdigest(),
                first_bytes=data[:8],
                archive_members=members,
                archive_encrypted=encrypted,
                archive_error=archive_error,
            ))
        elif content_type == "text/plain":
            text_parts.append(_part_text(part))
        elif content_type == "text/html":
            html_parts.append(_part_text(part))

    text_body = "\n".join(text_parts)
    html_body = "\n".join(html_parts)

    # 4. Package everything up.
    return ParsedEmail(
        from_name=from_name,
        from_address=from_address.lower(),
        reply_to=parseaddr(_header(msg, "Reply-To"))[1].lower(),
        return_path=parseaddr(_header(msg, "Return-Path"))[1].lower(),
        to=_header(msg, "To"),
        subject=_header(msg, "Subject"),
        date=_header(msg, "Date"),
        message_id=_header(msg, "Message-ID"),
        received_chain=_all_headers(msg, "Received"),
        auth_results=_all_headers(msg, "Authentication-Results"),
        text_body=text_body,
        html_body=html_body,
        links=_extract_links(text_body, html_body),
        attachments=attachments,
    )
