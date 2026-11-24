"""
Check an email file for phishing and print a report.

Usage:
    python3 main.py samples/sample_phish.eml
    python3 main.py samples/sample_phish.eml --details   (also shows the parsed email)
"""

import sys
from pathlib import Path

from detector.parser import MAX_EMAIL_SIZE, EmailParseError, parse_email
from detector.scoring import analyze_email
from detector.urls import defang

SEVERITY_LABELS = {"high": "[HIGH]  ", "medium": "[MEDIUM]", "low": "[LOW]   ", "info": "[INFO]  "}


def preview(text, limit=200):
    """Show only the start of the body. No need to dump private email content."""
    text = " ".join(text.split())
    return text[:limit] + ("..." if len(text) > limit else "")


def load_email(path):
    """Check the file, then parse it. Exits with a clear message on any problem."""
    if not path.is_file():
        sys.exit(f"Error: '{path}' is not a file.")
    if path.stat().st_size > MAX_EMAIL_SIZE:
        sys.exit("Error: file is larger than the 10 MB limit.")
    try:
        return parse_email(path.read_bytes())
    except EmailParseError as err:
        sys.exit(f"Error: {err}")


def print_parsed(email):
    print("=" * 60)
    print("PARSED EMAIL")
    print("=" * 60)
    print(f"From:         {email.from_name} <{email.from_address}>")
    print(f"Reply-To:     {email.reply_to or '(none)'}")
    print(f"Return-Path:  {email.return_path or '(none)'}")
    print(f"Subject:      {email.subject}")
    print(f"Date:         {email.date}")
    print(f"Body preview: {preview(email.text_body or email.html_body)}")
    print(f"Links:        {len(email.links)}")
    for link in email.links:
        print(f"  Goes to: {defang(link.url)}")
        if link.display_text:
            print(f"  Shows:   {link.display_text}")
    print(f"Attachments:  {len(email.attachments)}")
    for att in email.attachments:
        print(f"  {att.filename} ({att.content_type}, {att.size_bytes} bytes)")
    print()


def print_report(email, report):
    bar = "#" * (report.score // 5) + "-" * (20 - report.score // 5)

    print("=" * 60)
    print(f"VERDICT: {report.verdict.upper()}")
    print(f"Risk score: {report.score}/100  [{bar}]")
    print("=" * 60)
    print(f"Subject: {email.subject}")
    print(f"From:    {email.from_name} <{email.from_address}>")

    if report.top_reasons:
        print("\nTop reasons:")
        for i, f in enumerate(report.top_reasons, 1):
            print(f"  {i}. {f.message}")

    print(f"\nWhat to do: {report.advice}")

    print("\n" + "-" * 60)
    print("ALL FINDINGS")
    print("-" * 60)
    print(f"SPF: {report.auth['spf']}   DKIM: {report.auth['dkim']}   DMARC: {report.auth['dmarc']}")
    for category, findings in report.by_category.items():
        points = report.category_points[category]
        print(f"\n{category} ({points} pts)")
        if not findings:
            print("  Nothing found.")
        for f in findings:
            print(f"  {SEVERITY_LABELS[f.severity]} {f.message}")

    print("\n" + "-" * 60)
    print("LIMITS OF THIS CHECK")
    print("-" * 60)
    for note in report.notes:
        print(f"  - {note}")


def main():
    args = [a for a in sys.argv[1:] if a != "--details"]
    if len(args) != 1:
        sys.exit("Usage: python3 main.py path/to/email.eml [--details]")

    email = load_email(Path(args[0]))
    if "--details" in sys.argv:
        print_parsed(email)
    print_report(email, analyze_email(email))


if __name__ == "__main__":
    main()
