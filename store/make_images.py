"""
Make the Chrome Web Store images from the REAL extension running in Chrome.

    python3 store/make_images.py

Writes to store/images/:
- screenshot-1-scam.png, -2-links.png, -3-safe.png, -4-popup.png  (1280x800)
- promo-small-440x280.png                                           (small promo tile)
- icon-128.png                                                      (store icon)

The inbox in the screenshots is a plain, unbranded page we draw ourselves,
so the listing never looks like it comes from Google. It still has the
same structure as Gmail, so the extension runs exactly as it does for real.
Needs Playwright and a Chrome that can load unpacked extensions.
"""

import base64
import importlib.util
import sys
import tempfile
from pathlib import Path

from PIL import Image
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "store" / "images"
EXT = ROOT / "extension"

# Reuse the fake mail server from the end-to-end test.
spec = importlib.util.spec_from_file_location("e2e", ROOT / "dev" / "e2e_extension.py")
e2e = importlib.util.module_from_spec(spec)
spec.loader.exec_module(e2e)

SHELL = """<!DOCTYPE html><html><head><title>Inbox</title>
<script>var GLOBALS=[null,null,1,"x","y",null,0,"z","w","IK",1];</script>
<style>
  body { margin: 0; font-family: Roboto, Arial, sans-serif; background: #eef1f6; }
  .cap { background: #1f3f9a; color: #fff; padding: 26px 48px; }
  .cap h1 { margin: 0; font: 600 30px Roboto, Arial; }
  .cap p { margin: 6px 0 0; font: 18px Roboto, Arial; opacity: .9; }
  .bar { background: #fff; padding: 12px 48px; font: 500 17px Arial; color: #444; border-bottom: 1px solid #dde2ea; }
  #thread { max-width: 1060px; margin: 22px auto; background: #fff; padding: 8px 26px 16px; border-radius: 14px; }
  .adn h2 { font-size: 24px !important; }
</style></head>
<body><div class="cap"><h1>CAPTION</h1><p>SUBCAPTION</p></div>
<div class="bar">Inbox</div><div id="thread"></div></body></html>"""

SHOTS = [
    ("screenshot-1-scam.png", "18c2f0a1b2c3d4e5",
     "Catches scams with no bad links at all",
     "Gift card requests, secrecy and urgency, from a free email account.",
     "Hi, are you at your desk? I need you to handle something for me quickly. I'm in a meeting and can't talk right now..."),
    ("screenshot-2-links.png", "18c2f0a1b2c3d4e7",
     "Spots links that lie about where they go",
     "Raw IP addresses, the '@' trick, fake subdomains, and shortened links.",
     "Your package could not be delivered. Pay the $1.99 redelivery fee to release it."),
    ("screenshot-3-safe.png", "18c2f0a1b2c3d4e6",
     "Stays quiet on normal email",
     "Real emails get a green banner, not a false alarm.",
     "Hi Joe, good news. Your order #48213 has shipped and should arrive Thursday."),
]


def fit(html):
    return html.replace("IK", e2e.FAKE_IK)


def page_from_html(ctx, html, size):
    page = ctx.new_page()
    page.set_viewport_size(size)
    page.set_content(html)
    return page


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as p, tempfile.TemporaryDirectory() as profile:
        ctx = p.chromium.launch_persistent_context(
            profile, executable_path="/usr/bin/google-chrome", headless=True,
            viewport={"width": 1280, "height": 800}, device_scale_factor=1,
            args=["--no-sandbox", f"--disable-extensions-except={EXT}", f"--load-extension={EXT}"])
        sw = ctx.service_workers[0] if ctx.service_workers else ctx.wait_for_event("serviceworker")
        ext_id = sw.url.split("/")[2]
        sw.evaluate("""async () => { for (let i = 0; i < 120; i++) {
            const s = await builtinAsk({ type: 'status' }); if (s.status === 'ready') return;
            await new Promise((r) => setTimeout(r, 500)); } }""")

        # 1-3: the extension running on real samples
        for name, hex_id, cap, sub, body in SHOTS:
            e2e.INBOX = fit(SHELL.replace("SUBCAPTION", sub).replace("CAPTION", cap))  # SUBCAPTION first: it contains "CAPTION"
            ctx.unroute("https://mail.google.com/**")
            ctx.route("https://mail.google.com/**", e2e.fake_gmail)
            page = ctx.new_page()
            page.goto("https://mail.google.com/mail/u/0/#inbox")
            _, sender, subject = e2e.MESSAGES[hex_id]
            e2e.open_email(page, hex_id, sender, subject, body)
            e2e.wait_for_banner(page, name)
            page.screenshot(path=str(OUT / name))
            page.close()
            print("wrote", name)

        # 4: the popup, shown large on a caption card
        popup = ctx.new_page()
        # Draw the popup at 1.7x size (CSS zoom) so it's sharp, not a stretched small image.
        popup.set_viewport_size({"width": 510, "height": 372})
        popup.goto(f"chrome-extension://{ext_id}/popup.html")
        popup.wait_for_timeout(1000)
        popup.evaluate("() => { document.documentElement.style.zoom = '1.7'; }")
        popup.wait_for_timeout(200)
        popup_png = base64.b64encode(popup.screenshot()).decode()
        popup.close()
        card = page_from_html(ctx, f"""<html><body style="margin:0;width:1280px;height:800px;display:flex;
            align-items:center;justify-content:center;gap:70px;background:#eef1f6;font-family:Roboto,Arial">
            <div style="max-width:470px"><h1 style="font:600 40px Roboto,Arial;color:#1f3f9a;margin:0 0 18px">
            Runs on your computer</h1><p style="font:22px/1.5 Roboto,Arial;color:#333;margin:0">
            The detector is built into the extension. Your emails are never uploaded, stored, or shared.
            No account, no tracking, no ads.</p></div>
            <img src="data:image/png;base64,{popup_png}" style="width:510px;border-radius:14px;
            box-shadow:0 10px 40px rgba(0,0,0,.18);background:#fff"></body></html>""",
            {"width": 1280, "height": 800})
        card.screenshot(path=str(OUT / "screenshot-4-popup.png"))
        card.close()
        print("wrote screenshot-4-popup.png")

        # Small promo tile, 440x280
        icon = base64.b64encode((EXT / "icons" / "128.png").read_bytes()).decode()
        tile = page_from_html(ctx, f"""<html><body style="margin:0;width:440px;height:280px;display:flex;
            flex-direction:column;align-items:center;justify-content:center;background:#1f3f9a;color:#fff;
            font-family:Roboto,Arial;text-align:center">
            <img src="data:image/png;base64,{icon}" style="width:84px;height:84px;filter:drop-shadow(0 4px 10px rgba(0,0,0,.25))">
            <div style="font:700 30px Roboto,Arial;margin-top:14px">Phishing Email Detector</div>
            <div style="font:17px Roboto,Arial;margin-top:6px;opacity:.9">Checks Gmail on your own computer</div>
            </body></html>""", {"width": 440, "height": 280})
        tile.screenshot(path=str(OUT / "promo-small-440x280.png"))
        tile.close()
        print("wrote promo-small-440x280.png")
        ctx.close()

    # Store icon: 128x128 with the artwork at 96x96 and transparent padding,
    # the layout Chrome's image guidelines recommend.
    art = Image.open(EXT / "icons" / "128.png").convert("RGBA").resize((96, 96), Image.LANCZOS)
    icon128 = Image.new("RGBA", (128, 128), (0, 0, 0, 0))
    icon128.paste(art, (16, 16), art)
    icon128.save(OUT / "icon-128.png")
    print("wrote icon-128.png")

    for f in sorted(OUT.glob("*.png")):
        print(f"  {f.name}: {Image.open(f).size}")


if __name__ == "__main__":
    sys.exit(main())
