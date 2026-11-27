# Renders store/images/promo-marquee-1400x560.png. Run from the project folder after store/make_images.py and dev/e2e_extension.py.
import base64
from PIL import Image
from playwright.sync_api import sync_playwright
icon = base64.b64encode(open("extension/icons/128.png", "rb").read()).decode()
shot = base64.b64encode(open("dev/screenshots/gmail_ceo_fraud.png", "rb").read()).decode()
with sync_playwright() as p:
    b = p.chromium.launch(executable_path="/usr/bin/google-chrome", args=["--no-sandbox"])
    pg = b.new_page(viewport={"width": 1400, "height": 560}, device_scale_factor=1)
    pg.set_content(f"""<html><body style="margin:0;width:1400px;height:560px;overflow:hidden;
      background:linear-gradient(120deg,#1f3f9a,#2f5bd3);font-family:Roboto,Arial;color:#fff;position:relative">
      <div style="position:absolute;left:80px;top:0;bottom:0;width:620px;display:flex;flex-direction:column;justify-content:center">
        <img src="data:image/png;base64,{icon}" style="width:96px;height:96px;filter:drop-shadow(0 6px 14px rgba(0,0,0,.25))">
        <div style="font:700 50px/1.1 Roboto,Arial;margin-top:22px">Phishing Email Detector</div>
        <div style="font:24px/1.45 Roboto,Arial;margin-top:16px;opacity:.92">Clear warnings on scam emails in Gmail.<br>Checked on your own computer. Nothing is sent online.</div>
      </div>
      <div style="position:absolute;right:-40px;top:60px;width:720px;height:470px;overflow:hidden;border-radius:16px;
        box-shadow:0 18px 50px rgba(0,0,0,.35);background:#fff">
        <img src="data:image/png;base64,{shot}" style="width:900px;margin:-60px 0 0 -20px">
      </div></body></html>""")
    pg.wait_for_timeout(300)
    pg.screenshot(path="store/images/promo-marquee-1400x560.png")
    b.close()
print(Image.open("store/images/promo-marquee-1400x560.png").size)
