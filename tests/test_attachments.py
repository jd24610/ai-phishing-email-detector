"""
Tests for attachment checks.

Run from the project folder with:
    python3 -m unittest discover tests
"""

import unittest
from pathlib import Path

from detector.attachments import analyze_attachments, check_attachment, extensions
from detector.parser import Attachment, parse_email

SAMPLES = Path(__file__).parent.parent / "samples"


def att(name, first_bytes=b""):
    """Build a fake attachment record. No real file involved."""
    return Attachment(filename=name, content_type="application/octet-stream",
                      size_bytes=100, sha256="0" * 64, first_bytes=first_bytes)


def messages(findings):
    return " | ".join(f.message for f in findings)


class TestAttachmentTricks(unittest.TestCase):

    def test_exe(self):
        self.assertEqual(check_attachment(att("setup.exe"))[0].severity, "high")

    def test_double_extension(self):
        self.assertIn("double extension", messages(check_attachment(att("invoice.pdf.exe"))))

    def test_double_extension_with_caps_and_spaces(self):
        self.assertIn("double extension", messages(check_attachment(att("Invoice.PDF. exe"))))

    def test_right_to_left_override(self):
        # Shows on screen as "invoiceexe.pdf" but is really "invoice[RLO]fdp.exe"
        self.assertIn("reverses the text", messages(check_attachment(att("invoice‮fdp.exe"))))

    def test_macro_office(self):
        self.assertIn("macros", messages(check_attachment(att("bonus.xlsm"))))

    def test_html_attachment(self):
        self.assertIn("fake login page", messages(check_attachment(att("form.html"))))

    def test_disguised_program(self):
        f = check_attachment(att("scan.pdf", b"MZ\x90\x00"))
        self.assertIn("really a Windows program", messages(f))

    def test_attach_sample(self):
        email = parse_email((SAMPLES / "sample_phish_attach.eml").read_bytes())
        self.assertEqual(len(email.attachments), 4)
        text = messages(analyze_attachments(email))
        for clue in ["double extension", "fake login page", "macros", "really a Windows program"]:
            self.assertIn(clue, text)


class TestArchives(unittest.TestCase):

    def setUp(self):
        self.email = parse_email((SAMPLES / "sample_phish_zip.eml").read_bytes())
        self.by_name = {a.filename: a for a in self.email.attachments}

    def test_lists_zip_contents_without_unzipping(self):
        members = self.by_name["Invoice_2026.zip"].archive_members
        self.assertIn("Invoice_2026/Invoice_2026.pdf.exe", members)

    def test_program_hidden_in_zip(self):
        f = check_attachment(self.by_name["Invoice_2026.zip"])
        self.assertIn("hides dangerous files inside", messages(f))
        self.assertIn("fake .pdf, really .exe", messages(f))

    def test_password_protected_zip(self):
        a = self.by_name["Secure_Files.zip"]
        self.assertTrue(a.archive_encrypted)
        self.assertIn("password-protected", messages(check_attachment(a)))

    def test_zip_inside_zip(self):
        self.assertIn("another archive", messages(check_attachment(self.by_name["Archive.zip"])))

    def test_broken_zip(self):
        a = att("files.zip", b"PK\x03\x04")
        a.archive_error = "Could not read archive: BadZipFile"
        self.assertIn("could not be checked", messages(check_attachment(a)))

    def test_docx_with_hidden_macros(self):
        a = att("report.docx", b"PK\x03\x04")
        a.archive_members = ["word/document.xml", "word/vbaProject.bin"]
        self.assertIn("macro code", messages(check_attachment(a)))

    def test_clean_zip_only_gets_low(self):
        a = att("photos.zip", b"PK\x03\x04")
        a.archive_members = ["beach.jpg", "notes.txt", "report.pdf"]
        self.assertTrue(all(f.severity == "low" for f in check_attachment(a)))


class TestNoFalseAlarms(unittest.TestCase):

    def test_real_pdf(self):
        self.assertEqual(check_attachment(att("statement.pdf", b"%PDF-1.7")), [])

    def test_real_photo(self):
        self.assertEqual(check_attachment(att("photo.jpg", b"\xff\xd8\xff\xe0")), [])

    def test_real_docx(self):
        # .docx files are ZIPs inside, so "PK" bytes are normal here.
        a = att("resume.docx", b"PK\x03\x04")
        a.archive_members = ["word/document.xml", "word/styles.xml"]
        self.assertEqual(check_attachment(a), [])

    def test_dots_in_normal_name(self):
        self.assertEqual(check_attachment(att("Q4.2026.report.pdf", b"%PDF-1.4")), [])


class TestHelpers(unittest.TestCase):

    def test_extensions(self):
        self.assertEqual(extensions("Invoice.PDF.exe"), ["pdf", "exe"])
        self.assertEqual(extensions("noext"), [])


if __name__ == "__main__":
    unittest.main()
