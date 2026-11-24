"""
End-to-end test for the Chrome extension, using a FAKE Gmail.

What it does:
1. Starts the local detector server.
2. Opens Chrome with the extension loaded.
3. Answers every request to mail.google.com with a fake Gmail page we
   control, including fake "Show original" pages built from our samples.
4. Opens emails and checks that the extension scans them and shows banners.
5. Saves screenshots to dev/screenshots/.

This is a developer tool. It needs Playwright and a Chrome that can load
unpacked extensions (Chrome for Testing or Chromium):
    pip install playwright
    python3 dev/e2e_extension.py --chrome /path/to/chrome

The fake page copies only what the extension relies on: the
data-legacy-message-id attribute, the .a3s body, and the view=om URL.
Real Gmail can change those at any time, so also test on real Gmail.
"""

import argparse
import html
from urllib.parse import parse_qs, urlsplit
import tempfile
import threading
from pathlib import Path

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parent.parent
import sys
sys.path.insert(0, str(ROOT))
from server import OUR_EXTENSION_ID, make_server  # noqa: E402

EXT = ROOT / "extension"
SHOTS = ROOT / "dev" / "screenshots"
SAMPLES = ROOT / "samples"

# Fake Gmail message IDs (hex) -> which sample email they hold.
MESSAGES = {
    "18c2f0a1b2c3d4e5": ("sample_ceo_fraud.eml", "David Chen CEO", "Quick favor"),
    "18c2f0a1b2c3d4e6": ("sample_legit.eml", "Shop Example", "Your order #48213 has shipped"),
    "18c2f0a1b2c3d4e7": ("sample_phish_links.eml", "Delivery Notice", "Package on hold: action required"),
}
MISSING_ID = "18c2f0a1b2c3d4e8"  # "Show original" will fail for this one


def perm(hex_id):
    return f"msg-f:{int(hex_id, 16)}"


def message_html(hex_id, sender, subject, body="(email body)"):
    return f"""
    <div class="adn ads" data-legacy-message-id="{hex_id}" style="border:1px solid #ddd;margin:12px 0;padding:12px;border-radius:8px">
      <h2 style="font:500 20px Arial;margin:0 0 4px">{html.escape(subject)}</h2>
      <div style="color:#555;font:13px Arial;margin-bottom:8px">{html.escape(sender)}</div>
      <div class="gs"><div class="ii gt"><div class="a3s" style="font:14px Arial">{html.escape(body)}</div></div></div>
    </div>"""


INBOX = """<!DOCTYPE html><html><head><title>Inbox - Gmail (fake)</title></head>
<body style="margin:0;font-family:Arial;background:#f6f8fc">
<div style="background:#fff;padding:10px 16px;font:500 18px Arial;border-bottom:1px solid #ddd">Gmail (fake test page)</div>
<div id="thread" style="max-width:820px;margin:16px auto;background:#fff;padding:8px 20px;border-radius:12px"></div>
</body></html>"""


def fake_gmail(route):
    url = route.request.url
    query = parse_qs(urlsplit(url).query)  # decodes %3A back to ":" like a real server
    if query.get("view") == ["om"]:
        for hex_id, (sample, *_rest) in MESSAGES.items():
            if query.get("permmsgid") == [perm(hex_id)]:
                raw = (SAMPLES / sample).read_text(errors="replace")
                page = f'<html><body><pre class="raw_message_text" id="raw_message_text">{html.escape(raw)}</pre></body></html>'
                return route.fulfill(status=200, content_type="text/html", body=page)
        return route.fulfill(status=404, content_type="text/html", body="Not found")
    return route.fulfill(status=200, content_type="text/html", body=INBOX)


def open_email(page, hex_id, sender, subject, body):
    """Simulate Gmail swapping in a new opened message (no page reload)."""
    page.evaluate("(h) => { document.getElementById('thread').innerHTML = h; }",
                  message_html(hex_id, sender, subject, body))


def wait_for_banner(page, text_hint, timeout=8000):
    """The banner's shadow root is closed, so we wait on the server instead."""
    page.wait_for_timeout(300)
    page.wait_for_function("() => !!document.querySelector('phish-detector-banner')", timeout=timeout)
    page.wait_for_timeout(1500)  # give the scan time to finish and render


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--chrome", default="/usr/bin/google-chrome")
    args = ap.parse_args()
    SHOTS.mkdir(parents=True, exist_ok=True)

    server = make_server(port=8765)
    requests = []
    original_log = server.RequestHandlerClass.log_message
    server.RequestHandlerClass.log_message = lambda self, fmt, *a: requests.append(
        (self.command, self.path, self.headers.get("Origin"), a[1] if len(a) > 1 else ""))
    threading.Thread(target=server.serve_forever, daemon=True).start()

    try:
        with sync_playwright() as p, tempfile.TemporaryDirectory() as profile:
            ctx = p.chromium.launch_persistent_context(
                profile, executable_path=args.chrome, headless=True,
                viewport={"width": 900, "height": 760}, device_scale_factor=1.5,
                args=["--no-sandbox", f"--disable-extensions-except={EXT}", f"--load-extension={EXT}"])
            ctx.route("https://mail.google.com/**", fake_gmail)

            # Extension loaded with the expected fixed ID?
            sw = ctx.service_workers[0] if ctx.service_workers else ctx.wait_for_event("serviceworker")
            ext_id = sw.url.split("/")[2]
            print(f"Extension loaded. ID: {ext_id} (expected {OUR_EXTENSION_ID})")
            assert ext_id == OUR_EXTENSION_ID

            page = ctx.new_page()
            page.goto("https://mail.google.com/mail/u/0/#inbox")

            checks = [
                ("18c2f0a1b2c3d4e5", "ceo_fraud", "Are you at your desk? I need you to handle something for me quickly..."),
                ("18c2f0a1b2c3d4e6", "legit", "Good news. Your order #48213 has shipped and should arrive Thursday."),
                ("18c2f0a1b2c3d4e7", "links", "Your package could not be delivered. Pay the $1.99 redelivery fee."),
            ]
            for hex_id, name, body in checks:
                _, sender, subject = MESSAGES[hex_id]
                open_email(page, hex_id, sender, subject, body)
                wait_for_banner(page, name)
                page.screenshot(path=str(SHOTS / f"gmail_{name}.png"))
                print(f"Opened {name}: banner shown")

            # Gmail "Show original" fails -> friendly error, no crash
            open_email(page, MISSING_ID, "Someone", "Broken one", "hello")
            wait_for_banner(page, "missing")
            page.screenshot(path=str(SHOTS / "gmail_error.png"))
            print("Opened message with no original: error banner shown")

            # Re-opening an email uses the saved result instead of scanning again
            before = sum(1 for r in requests if r[1] == "/api/analyze")
            _, sender, subject = MESSAGES["18c2f0a1b2c3d4e5"]
            open_email(page, "18c2f0a1b2c3d4e5", sender, subject, "again")
            wait_for_banner(page, "again")
            after = sum(1 for r in requests if r[1] == "/api/analyze")
            print(f"Re-opened an email: {after - before} new scans (expected 0)")
            assert after == before

            # Popup
            popup = ctx.new_page()
            popup.set_viewport_size({"width": 300, "height": 260})
            popup.goto(f"chrome-extension://{ext_id}/popup.html")
            popup.wait_for_timeout(800)
            popup.screenshot(path=str(SHOTS / "popup.png"))
            print("Popup says detector is:", popup.text_content("#server"))

            # Turn auto-scan off: a new email should NOT be scanned
            popup.click("#auto")
            popup.wait_for_timeout(300)
            before = sum(1 for r in requests if r[1] == "/api/analyze")
            _, sender, subject = MESSAGES["18c2f0a1b2c3d4e6"]
            page.bring_to_front()
            open_email(page, "18c2f0a1b2c3d4e6", sender + " ", subject, "auto-scan off test")
            page.evaluate("() => document.querySelector('[data-legacy-message-id]').setAttribute('data-legacy-message-id', 'aaaaaaaaaaaaaaaa')")
            page.wait_for_timeout(1500)
            after = sum(1 for r in requests if r[1] == "/api/analyze")
            print(f"Auto-scan off: {after - before} new scans (expected 0)")
            assert after == before
            ctx.close()
    finally:
        server.RequestHandlerClass.log_message = original_log
        server.shutdown()
        server.server_close()

    analyze = [r for r in requests if r[1] == "/api/analyze"]
    origins = {r[2] for r in analyze}
    print(f"\nServer got {len(analyze)} scan requests, all from: {origins}")
    assert origins == {f"chrome-extension://{OUR_EXTENSION_ID}"}
    print("ALL EXTENSION CHECKS PASSED")


if __name__ == "__main__":
    main()
