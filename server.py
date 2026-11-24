"""
Local web server for the phishing detector.

Runs on YOUR computer only. Open http://127.0.0.1:8765 in your browser,
drop in an .eml file, and see the report. Later, the Chrome extension
will send emails here too.

Usage:
    python3 server.py
    python3 server.py --port 9000

Uses only Python's standard library.

Security choices (a local server is still a server):
1. Listens on 127.0.0.1 only. Other devices on your Wi-Fi can't reach it.
2. Checks the Host header. This blocks "DNS rebinding," a trick where a
   website you visit makes your browser talk to your local server.
3. Checks the Origin header. Random websites can't send emails here or
   read the results. Only this page and (later) our own extension can.
4. Size limit on uploads, same 10 MB as the parser.
5. Never logs email content. Logs only the method, path, and status.
6. Strict security headers on every response, including a Content
   Security Policy that blocks inline scripts.
7. Serves a fixed list of files only, so "../../secret" paths can't work.
"""

import argparse
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from detector.parser import MAX_EMAIL_SIZE, EmailParseError, parse_email
from detector.scoring import analyze_email

HOST = "127.0.0.1"
DEFAULT_PORT = 8765
WEB_DIR = Path(__file__).parent / "web"

# Exact files the server is allowed to send. Nothing else on disk is reachable.
STATIC_FILES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/style.css": ("style.css", "text/css; charset=utf-8"),
}

SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; "
                               "img-src 'self' data:; object-src 'none'; frame-ancestors 'none'; "
                               "base-uri 'none'; form-action 'none'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}


def extension_origins():
    """
    Chrome extension IDs allowed to call the API, from an environment variable:
        PHISH_EXTENSION_IDS=abcdefghijklmnop...   (comma-separated)
    Empty by default, so no extension is trusted until you say so.
    """
    ids = os.environ.get("PHISH_EXTENSION_IDS", "")
    return {f"chrome-extension://{i.strip()}" for i in ids.split(",") if i.strip()}


def report_to_dict(email, report):
    """Turn a Report into plain JSON. Leaves out the email body on purpose."""
    def finding(f):
        return {"check": f.check, "severity": f.severity, "message": f.message}

    return {
        "verdict": report.verdict,
        "score": report.score,
        "advice": report.advice,
        "email": {
            "from_name": email.from_name,
            "from_address": email.from_address,
            "subject": email.subject,
            "links": len(email.links),
            "attachments": len(email.attachments),
        },
        "auth": report.auth,
        "top_reasons": [finding(f) for f in report.top_reasons],
        "categories": [
            {"name": name, "points": report.category_points[name],
             "findings": [finding(f) for f in findings]}
            for name, findings in report.by_category.items()
        ],
        "notes": report.notes,
    }


class Handler(BaseHTTPRequestHandler):
    server_version = "PhishDetector"
    sys_version = ""

    # ---------- helpers ----------

    def allowed_hosts(self):
        port = self.server.server_address[1]
        return {f"127.0.0.1:{port}", f"localhost:{port}"}

    def allowed_origins(self):
        return {f"http://{h}" for h in self.allowed_hosts()} | extension_origins()

    def send_json(self, status, data, origin=None):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
        for k, v in SECURITY_HEADERS.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def error(self, status, message, origin=None):
        self.send_json(status, {"error": message}, origin)

    def host_ok(self):
        """Block DNS rebinding: the Host header must be our own address."""
        if self.headers.get("Host", "") not in self.allowed_hosts():
            self.error(403, "Bad Host header.")
            return False
        return True

    def log_message(self, fmt, *args):
        # Default logging prints the request line only. We keep that format
        # but never print headers or bodies, so no email content hits the logs.
        if getattr(self.server, "quiet", False):
            return
        sys.stderr.write(f"{self.address_string()} - {fmt % args}\n")

    # ---------- routes ----------

    def do_GET(self):
        if not self.host_ok():
            return
        if self.path == "/api/health":
            return self.send_json(200, {"status": "ok"})

        if self.path not in STATIC_FILES:
            return self.error(404, "Not found.")
        name, ctype = STATIC_FILES[self.path]
        body = (WEB_DIR / name).read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in SECURITY_HEADERS.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        """Browsers ask permission (a "preflight") before cross-origin POSTs."""
        if not self.host_ok():
            return
        origin = self.headers.get("Origin", "")
        if self.path != "/api/analyze" or origin not in self.allowed_origins():
            return self.error(403, "Origin not allowed.")
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", origin)
        self.send_header("Access-Control-Allow-Methods", "POST")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Max-Age", "600")
        self.send_header("Vary", "Origin")
        self.end_headers()

    def do_POST(self):
        if not self.host_ok():
            return
        if self.path != "/api/analyze":
            return self.error(404, "Not found.")

        # Browsers always send Origin on POSTs from web pages. If it's there,
        # it must be on our list. (Command-line tools like curl send none.)
        origin = self.headers.get("Origin")
        if origin is not None and origin not in self.allowed_origins():
            return self.error(403, "Origin not allowed.")

        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            return self.error(411, "Content-Length is required.", origin)
        if length <= 0:
            return self.error(400, "The upload is empty.", origin)
        if length > MAX_EMAIL_SIZE:
            return self.error(413, "The file is larger than the 10 MB limit.", origin)

        raw = self.rfile.read(length)
        try:
            email = parse_email(raw)
        except EmailParseError as err:
            return self.error(400, str(err), origin)
        except Exception:
            # Don't leak internal details. Log the type only, never the email.
            sys.stderr.write("Unexpected error while parsing an upload.\n")
            return self.error(500, "Something went wrong while reading this email.", origin)

        self.send_json(200, report_to_dict(email, analyze_email(email)), origin)


def make_server(port=DEFAULT_PORT, quiet=False):
    server = ThreadingHTTPServer((HOST, port), Handler)
    server.quiet = quiet  # tests turn logging off
    return server


def main():
    parser = argparse.ArgumentParser(description="Local phishing detector server")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    args = parser.parse_args()

    server = make_server(args.port)
    print(f"Phishing detector running at http://{HOST}:{args.port}")
    print("Only this computer can reach it. Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
