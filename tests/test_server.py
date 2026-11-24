"""
Tests for the local web server.

Starts a real server on a free port, sends real HTTP requests, and
checks the answers. Run with:
    python3 -m unittest discover tests
"""

import http.client
import json
import os
import threading
import unittest
from pathlib import Path

from server import make_server

SAMPLES = Path(__file__).parent.parent / "samples"


class ServerTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.server = make_server(port=0, quiet=True)           # port 0 = pick any free port
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def request(self, method, path, body=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        h = {"Host": f"127.0.0.1:{self.port}"}
        h.update(headers or {})
        conn.request(method, path, body=body, headers=h)
        resp = conn.getresponse()
        data = resp.read()
        conn.close()
        return resp, data

    def post_email(self, raw, origin=None):
        headers = {"Content-Type": "message/rfc822"}
        if origin:
            headers["Origin"] = origin
        return self.request("POST", "/api/analyze", raw, headers)

    # ---- normal use ----

    def test_health(self):
        resp, data = self.request("GET", "/api/health")
        self.assertEqual(resp.status, 200)
        self.assertEqual(json.loads(data), {"status": "ok"})

    def test_page_served_with_security_headers(self):
        resp, data = self.request("GET", "/")
        self.assertEqual(resp.status, 200)
        self.assertIn(b"Phishing Email Detector", data)
        self.assertIn("script-src 'self'", resp.getheader("Content-Security-Policy"))
        self.assertEqual(resp.getheader("X-Frame-Options"), "DENY")

    def test_analyze_phish(self):
        raw = (SAMPLES / "sample_ceo_fraud.eml").read_bytes()
        resp, data = self.post_email(raw, origin=f"http://127.0.0.1:{self.port}")
        self.assertEqual(resp.status, 200)
        report = json.loads(data)
        self.assertEqual(report["verdict"], "Likely phishing")
        self.assertTrue(report["top_reasons"])

    def test_body_not_returned(self):
        # The report should never echo the email body back.
        raw = (SAMPLES / "sample_ceo_fraud.eml").read_bytes()
        _, data = self.post_email(raw)
        self.assertNotIn(b"Scratch the back", data)

    # ---- bad input ----

    def test_not_an_email(self):
        resp, data = self.post_email(b"hello this is not an email")
        self.assertEqual(resp.status, 400)
        self.assertIn("From", json.loads(data)["error"])

    def test_too_big(self):
        # We only send the header claiming 11 MB. The server must refuse before reading.
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn.putrequest("POST", "/api/analyze", skip_host=True)
        conn.putheader("Host", f"127.0.0.1:{self.port}")
        conn.putheader("Content-Length", str(11 * 1024 * 1024))
        conn.endheaders()
        resp = conn.getresponse()
        self.assertEqual(resp.status, 413)
        conn.close()

    def test_unknown_path(self):
        resp, _ = self.request("GET", "/../../etc/passwd")
        self.assertEqual(resp.status, 404)

    # ---- attacks ----

    def test_random_website_blocked(self):
        # A page on evil.example tries to use your local detector.
        raw = (SAMPLES / "sample_legit.eml").read_bytes()
        resp, _ = self.post_email(raw, origin="https://evil.example")
        self.assertEqual(resp.status, 403)

    def test_random_website_preflight_blocked(self):
        resp, _ = self.request("OPTIONS", "/api/analyze",
                               headers={"Origin": "https://evil.example"})
        self.assertEqual(resp.status, 403)

    def test_dns_rebinding_blocked(self):
        # The browser thinks it's talking to evil.example, which now points at 127.0.0.1.
        resp, _ = self.request("GET", "/api/health", headers={"Host": "evil.example"})
        self.assertEqual(resp.status, 403)

    def test_allowed_extension(self):
        os.environ["PHISH_EXTENSION_IDS"] = "abcdefghijklmnopabcdefghijklmnop"
        try:
            origin = "chrome-extension://abcdefghijklmnopabcdefghijklmnop"
            resp, _ = self.request("OPTIONS", "/api/analyze", headers={"Origin": origin})
            self.assertEqual(resp.status, 204)
            self.assertEqual(resp.getheader("Access-Control-Allow-Origin"), origin)
        finally:
            del os.environ["PHISH_EXTENSION_IDS"]

    def test_our_extension_allowed_by_default(self):
        origin = "chrome-extension://amibjogglnglgnopfajdejkgeolfnljd"
        raw = (SAMPLES / "sample_legit.eml").read_bytes()
        resp, _ = self.post_email(raw, origin=origin)
        self.assertEqual(resp.status, 200)
        self.assertEqual(resp.getheader("Access-Control-Allow-Origin"), origin)

    def test_unknown_extension_blocked(self):
        resp, _ = self.request("OPTIONS", "/api/analyze",
                               headers={"Origin": "chrome-extension://someoneelsesextension"})
        self.assertEqual(resp.status, 403)


if __name__ == "__main__":
    unittest.main()
