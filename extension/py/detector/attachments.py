"""
Attachment checks.

Attachments are how a lot of malware gets in. One double-click on the
wrong file can install ransomware.

IMPORTANT: we never save, open, or run an attachment. We only look at:
- its name
- the type the email SAYS it is
- its first few bytes, which show what it REALLY is

Checks:
1. Dangerous file types (.exe, .js, .vbs, .iso, ...)
2. Office files that can hold macros (.docm, .xlsm)
3. HTML / SVG files, often used as fake login pages that open offline
4. Double extensions: "invoice.pdf.exe"
5. Hidden right-to-left text that flips the name: "invoice[RLO]fdp.exe"
6. Disguised files: named .pdf but the bytes say it's a Windows program
7. Archives (.zip, .rar) that can hide any of the above
8. What's inside a zip: programs, fake names, passwords, zips in zips,
   and Office files that secretly contain macros
"""

from detector.findings import Finding

# Files that can run code the moment you double-click them.
DANGEROUS = {
    "exe", "scr", "com", "pif", "bat", "cmd", "msi", "dll", "cpl",
    "js", "jse", "vbs", "vbe", "wsf", "wsh", "ps1", "hta", "jar",
    "lnk", "reg", "iso", "img", "vhd",
}
MACRO_OFFICE = {"docm", "dotm", "xlsm", "xltm", "xlam", "pptm", "potm", "ppam"}
WEB_FILES = {"html", "htm", "shtml", "xhtml", "svg"}
ARCHIVES = {"zip", "rar", "7z", "gz", "tar", "cab", "ace"}

# Normal-looking types that scammers put in front of a dangerous one.
DECOY_TYPES = {"pdf", "doc", "docx", "xls", "xlsx", "txt", "jpg", "jpeg", "png", "csv"}

# "File signatures": the first bytes of a file tell you its real type.
SIGNATURES = [
    (b"MZ", "a Windows program"),
    (b"%PDF", "a PDF"),
    (b"PK\x03\x04", "a ZIP archive (also used by .docx/.xlsx)"),
    (b"Rar!", "a RAR archive"),
    (b"7z\xbc\xaf", "a 7-Zip archive"),
    (b"\x89PNG", "a PNG image"),
    (b"\xff\xd8\xff", "a JPEG image"),
    (b"\xd0\xcf\x11\xe0", "an old Office file (.doc/.xls)"),
]

RTL_OVERRIDE = "‮"  # invisible character that flips text direction


def real_type(first_bytes):
    for signature, label in SIGNATURES:
        if first_bytes.startswith(signature):
            return label
    return None


def extensions(filename):
    """'Invoice.PDF.exe ' -> ['pdf', 'exe']"""
    name = filename.strip().strip(".").lower()
    parts = name.split(".")
    return [p.strip() for p in parts[1:]] if len(parts) > 1 else []


def check_attachment(att):
    findings = []
    name = att.filename
    exts = extensions(name)
    last = exts[-1] if exts else ""

    # 5. Right-to-left override
    if RTL_OVERRIDE in name:
        shown = name.replace(RTL_OVERRIDE, "")
        findings.append(Finding(
            "Attachment", "high",
            f"'{shown}' contains a hidden character that reverses the text, so a "
            "program can be made to look like a harmless file."))

    # 4. Double extension
    if len(exts) >= 2 and exts[-2] in DECOY_TYPES and last in DANGEROUS | MACRO_OFFICE | WEB_FILES:
        findings.append(Finding(
            "Attachment", "high",
            f"'{name}' has a double extension. It looks like a .{exts[-2]} file, "
            f"but it's really a .{last}. Windows often hides the last part."))
    # 1. Dangerous types
    elif last in DANGEROUS:
        findings.append(Finding(
            "Attachment", "high",
            f"'{name}' is a .{last} file, which can run code when opened. "
            "Legit businesses almost never email these."))

    # 2. Macro-enabled Office files
    if last in MACRO_OFFICE:
        findings.append(Finding(
            "Attachment", "medium",
            f"'{name}' is an Office file that can contain macros (small programs). "
            "Never click 'Enable Content' on a file you weren't expecting."))

    # 3. HTML and SVG
    if last in WEB_FILES:
        findings.append(Finding(
            "Attachment", "high" if last != "svg" else "medium",
            f"'{name}' is a web file. Scammers attach these because they open a fake "
            "login page right in your browser, and email filters often miss them."))

    # 7. Archives
    if last in ARCHIVES:
        findings.append(Finding(
            "Attachment", "low",
            f"'{name}' is a compressed archive. It may be fine, but archives are "
            "used to sneak dangerous files past email filters."))

    # 6. Disguised file: name says one thing, bytes say another
    actual = real_type(att.first_bytes)
    if actual == "a Windows program" and last not in DANGEROUS:
        findings.append(Finding(
            "Attachment", "high",
            f"'{name}' is named like a .{last or 'unknown'} file, but its contents "
            "show it's really a Windows program."))
    elif last == "pdf" and actual != "a PDF":
        findings.append(Finding(
            "Attachment", "low",
            f"'{name}' claims to be a PDF, but its contents don't look like one"
            + (f" (looks like {actual})." if actual else ".")))

    # 8. What's inside a zip (or a zip-based Office file)
    findings += check_archive_contents(att, last)

    return findings


def risky_inner_name(member):
    """Why a file name inside an archive is dangerous, or None if it looks fine."""
    base = member.replace("\\", "/").rsplit("/", 1)[-1]   # drop folder names
    exts = extensions(base)
    last = exts[-1] if exts else ""
    if RTL_OVERRIDE in base:
        return "hidden reversed-text trick"
    if len(exts) >= 2 and exts[-2] in DECOY_TYPES and last in DANGEROUS | WEB_FILES:
        return f"fake .{exts[-2]}, really .{last}"
    if last in DANGEROUS:
        return f".{last} program"
    if last in WEB_FILES:
        return "web page file"
    return None


def check_archive_contents(att, last):
    findings = []
    name = att.filename

    if att.archive_error:
        findings.append(Finding(
            "Attachment", "low",
            f"'{name}': {att.archive_error} Its contents could not be checked."))
        return findings

    # Office files (.docx, .xlsx) are zips inside. A "vbaProject.bin" part means macros.
    if last in ("docx", "xlsx", "pptx", "docm", "xlsm", "pptm") and any(
            m.lower().endswith("vbaproject.bin") for m in att.archive_members):
        if last not in MACRO_OFFICE:  # the .docm/.xlsm case is already flagged above
            findings.append(Finding(
                "Attachment", "medium",
                f"'{name}' contains macro code even though its name says it shouldn't."))
        return findings

    if last not in ARCHIVES:
        return findings

    if att.archive_encrypted:
        findings.append(Finding(
            "Attachment", "medium",
            f"'{name}' is password-protected, so nothing inside can be checked. Scammers do "
            "this on purpose and put the password in the email body."))

    risky = [(m, why) for m in att.archive_members if (why := risky_inner_name(m))]
    if risky:
        listed = ", ".join(f"'{m}' ({why})" for m, why in risky[:3])
        more = f" and {len(risky) - 3} more" if len(risky) > 3 else ""
        findings.append(Finding(
            "Attachment", "high",
            f"'{name}' hides dangerous files inside: {listed}{more}."))

    nested = [m for m in att.archive_members if (extensions(m) or [""])[-1] in ARCHIVES]
    if nested:
        findings.append(Finding(
            "Attachment", "low",
            f"'{name}' contains another archive ('{nested[0]}'). Zips inside zips are "
            "a trick to get past scanners that only look one level deep."))

    return findings


def analyze_attachments(email):
    """Takes a ParsedEmail. Returns a list of findings for all attachments."""
    findings = []
    for att in email.attachments:
        findings += check_attachment(att)
    return findings
