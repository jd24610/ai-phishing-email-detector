"""
End-to-end test for the Chrome extension, using a FAKE Gmail.

What it does:
1. Opens Chrome with the extension loaded. NO server is started: the
   extension must work on its own with its built-in (Pyodide) detector.
2. Checks the built-in detector gives the exact same report as the
   Python detector for every sample email.
3. Answers every request to mail.google.com with a fake Gmail page we
   control, including fake "Show original" pages built from our samples.
4. Opens emails and checks that the extension scans them, gets the right
   verdict, and shows banners.
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
import json
import tempfile
import time
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parent.parent
import sys
sys.path.insert(0, str(ROOT))
from detector.parser import parse_email  # noqa: E402
from detector.report import report_to_dict  # noqa: E402
from detector.scoring import analyze_email  # noqa: E402
from server import OUR_EXTENSION_ID  # noqa: E402

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


# Real Google emails can have 6,000+ characters of signature headers before "From:".
LONG_HEADERS = "".join(
    f"ARC-Message-Signature: i={i}; a=rsa-sha256; c=relaxed/relaxed; d=example.com;\r\n"
    f"        b={'Ab3' * 600}\r\n" for i in range(1, 4))


def perm(hex_id):
    return f"msg-f:{int(hex_id, 16)}"


def message_html(hex_id, sender, subject, body="(email body)"):
    return f"""
    <div class="adn ads" data-legacy-message-id="{hex_id}" style="border:1px solid #ddd;margin:12px 0;padding:12px;border-radius:8px">
      <h2 style="font:500 20px Arial;margin:0 0 4px">{html.escape(subject)}</h2>
      <div style="color:#555;font:13px Arial;margin-bottom:8px">{html.escape(sender)}</div>
      <div class="gs"><div class="ii gt"><div class="a3s" style="font:14px Arial">{html.escape(body)}</div></div></div>
    </div>"""


FAKE_IK = "a1b2c3d4e5"

# Real Gmail (checked 2026-11-24) puts its account key "ik" as the 10th item
# of a GLOBALS array in an inline script. Show original needs it.
INBOX = """<!DOCTYPE html><html><head><title>Inbox - Gmail (fake)</title>
<script>var GLOBALS=[null,null,1,"x","y",null,0,"z","w","FAKE_IK_HERE",1];</script></head>
<body style="margin:0;font-family:Arial;background:#f6f8fc">
<div style="background:#fff;padding:10px 16px;font:500 18px Arial;border-bottom:1px solid #ddd">Gmail (fake test page)</div>
<div id="thread" style="max-width:820px;margin:16px auto;background:#fff;padding:8px 20px;border-radius:12px"></div>
</body></html>""".replace("FAKE_IK_HERE", FAKE_IK)


def fake_gmail(route):
    url = route.request.url
    query = parse_qs(urlsplit(url).query)  # decodes %3A back to ":" like a real server
    if query.get("view") == ["om"] and query.get("ik") == [FAKE_IK]:
        for hex_id, (sample, *_rest) in MESSAGES.items():
            if query.get("permmsgid") == [perm(hex_id)]:
                raw = LONG_HEADERS + (SAMPLES / sample).read_text(errors="replace")
                page = f'<html><body><pre class="raw_message_text" id="raw_message_text">{html.escape(raw)}</pre></body></html>'
                return route.fulfill(status=200, content_type="text/html", body=page)
        return route.fulfill(status=404, content_type="text/html", body="Not found")
    return route.fulfill(status=200, content_type="text/html", body=INBOX,
                         headers={"Content-Security-Policy": "require-trusted-types-for 'script'"})


def open_email(page, hex_id, sender, subject, body):
    """Simulate Gmail swapping in a new opened message (no page reload)."""
    # The page has Trusted Types on (like real Gmail), so the fake Gmail
    # uses its own policy to update the page, just as Gmail does.
    page.evaluate("""(h) => {
        window.__fakeGmailPolicy ||= trustedTypes.createPolicy('fake-gmail', { createHTML: (s) => s });
        document.getElementById('thread').innerHTML = window.__fakeGmailPolicy.createHTML(h);
    }""", message_html(hex_id, sender, subject, body))


def wait_for_banner(page, text_hint, timeout=8000):
    """Wait for the banner (its shadow root is closed, so we can't read inside it)."""
    page.wait_for_timeout(300)
    page.wait_for_function("() => !!document.querySelector('phish-detector-banner')", timeout=timeout)
    page.wait_for_timeout(1500)  # give the scan time to finish and render


# Count scans and record verdicts from inside the extension's background worker.
SPY = """() => {
    if (self.__spy) return;
    self.__spy = true; self.__scans = 0; self.__verdicts = [];
    const real = builtinAsk;
    builtinAsk = async (m) => {
        const r = await real(m);
        if (m.type === 'analyze') { self.__scans++; self.__verdicts.push(r.ok ? r.report.verdict : 'error'); }
        return r;
    };
}"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--chrome", default="/usr/bin/google-chrome")
    args = ap.parse_args()
    SHOTS.mkdir(parents=True, exist_ok=True)

    with sync_playwright() as p, tempfile.TemporaryDirectory() as profile:
        ctx = p.chromium.launch_persistent_context(
            profile, executable_path=args.chrome, headless=True,
            viewport={"width": 900, "height": 760}, device_scale_factor=1.5,
            args=["--no-sandbox", f"--disable-extensions-except={EXT}", f"--load-extension={EXT}"])
        ctx.route("https://mail.google.com/**", fake_gmail)
        local_calls = []
        ctx.on("request", lambda r: "127.0.0.1" in r.url and local_calls.append(r.url))

        # 1. Extension loaded with the expected fixed ID?
        sw = ctx.service_workers[0] if ctx.service_workers else ctx.wait_for_event("serviceworker")
        ext_id = sw.url.split("/")[2]
        print(f"Extension loaded. ID: {ext_id} (expected {OUR_EXTENSION_ID})")
        assert ext_id == OUR_EXTENSION_ID

        # 2. Built-in detector starts, and matches the Python detector exactly.
        t = time.time()
        status = sw.evaluate("""async () => {
            for (let i = 0; i < 120; i++) {
                const s = await builtinAsk({ type: 'status' });
                if (s.status !== 'loading') return s;
                await new Promise((r) => setTimeout(r, 500));
            }
            return { status: 'timeout' };
        }""")
        print(f"Built-in detector: {status.get('status')} after {time.time() - t:.1f}s")
        assert status.get("status") == "ready"
        for f in sorted(SAMPLES.glob("*.eml")):
            raw = f.read_bytes().decode("utf-8", errors="replace")
            got = sw.evaluate("async (raw) => builtinAsk({ type: 'analyze', raw })", raw)
            email = parse_email(f.read_bytes())
            want = json.loads(json.dumps(report_to_dict(email, analyze_email(email))))
            assert got.get("ok") and got["report"] == want, f"{f.name}: built-in differs from Python"
        print(f"Built-in reports identical to Python for all {len(list(SAMPLES.glob('*.eml')))} samples")

        sw.evaluate(SPY)
        page = ctx.new_page()
        page.goto("https://mail.google.com/mail/u/0/#inbox")

        # 3. Open emails in fake Gmail: right verdict on each.
        checks = [
            ("18c2f0a1b2c3d4e5", "ceo_fraud", "Are you at your desk? I need you to handle something for me quickly...", "Likely phishing"),
            ("18c2f0a1b2c3d4e6", "legit", "Good news. Your order #48213 has shipped and should arrive Thursday.", "Low risk"),
            ("18c2f0a1b2c3d4e7", "links", "Your package could not be delivered. Pay the $1.99 redelivery fee.", "Likely phishing"),
        ]
        for hex_id, name, body, expected in checks:
            _, sender, subject = MESSAGES[hex_id]
            open_email(page, hex_id, sender, subject, body)
            wait_for_banner(page, name)
            page.screenshot(path=str(SHOTS / f"gmail_{name}.png"))
            verdict = sw.evaluate("() => self.__verdicts.at(-1)")
            print(f"Opened {name}: banner shown, verdict '{verdict}' (expected '{expected}')")
            assert verdict == expected

        # 4. Gmail "Show original" fails -> friendly error, no crash
        open_email(page, MISSING_ID, "Someone", "Broken one", "hello")
        wait_for_banner(page, "missing")
        page.screenshot(path=str(SHOTS / "gmail_error.png"))
        print("Opened message with no original: error banner shown")

        # 5. Re-opening an email uses the saved result instead of scanning again
        before = sw.evaluate("() => self.__scans")
        _, sender, subject = MESSAGES["18c2f0a1b2c3d4e5"]
        open_email(page, "18c2f0a1b2c3d4e5", sender, subject, "again")
        wait_for_banner(page, "again")
        after = sw.evaluate("() => self.__scans")
        print(f"Re-opened an email: {after - before} new scans (expected 0)")
        assert after == before

        # 6. Popup
        popup = ctx.new_page()
        popup.set_viewport_size({"width": 300, "height": 300})
        popup.goto(f"chrome-extension://{ext_id}/popup.html")
        popup.wait_for_timeout(800)
        popup.screenshot(path=str(SHOTS / "popup.png"))
        print("Popup says detector is:", popup.text_content("#status"))
        assert "ready" in popup.text_content("#status")

        # 7. Turn auto-scan off: a new email should NOT be scanned
        popup.click("#auto")
        popup.wait_for_timeout(300)
        before = sw.evaluate("() => self.__scans")
        _, sender, subject = MESSAGES["18c2f0a1b2c3d4e6"]
        page.bring_to_front()
        open_email(page, "18c2f0a1b2c3d4e6", sender + " ", subject, "auto-scan off test")
        page.evaluate("() => document.querySelector('[data-legacy-message-id]').setAttribute('data-legacy-message-id', 'aaaaaaaaaaaaaaaa')")
        page.wait_for_timeout(1500)
        after = sw.evaluate("() => self.__scans")
        print(f"Auto-scan off: {after - before} new scans (expected 0)")
        assert after == before
        ctx.close()

    # 8. Nothing tried to reach a local server.
    print(f"Requests to 127.0.0.1: {len(local_calls)} (expected 0)")
    assert not local_calls
    print("ALL EXTENSION CHECKS PASSED")


if __name__ == "__main__":
    main()
