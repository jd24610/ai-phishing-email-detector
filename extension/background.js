// Background service worker.
//
// This is the ONLY part of the extension that talks to the detector.
// Why not let the Gmail page script do it? A fetch from the Gmail tab
// would come from "mail.google.com", and our server (correctly) refuses
// requests from websites. From here, requests come from our own
// extension ID, which the server trusts.

const API = "http://127.0.0.1:8765";
const MAX_EMAIL_SIZE = 10 * 1024 * 1024;

async function health() {
  try {
    const res = await fetch(`${API}/api/health`, { cache: "no-store" });
    return { ok: res.ok };
  } catch {
    return { ok: false };
  }
}

async function analyze(raw) {
  try {
    const res = await fetch(`${API}/api/analyze`, {
      method: "POST",
      headers: { "Content-Type": "message/rfc822" },
      body: raw,
    });
    const data = await res.json();
    if (!res.ok) return { ok: false, error: data.error || "The detector couldn't read this email." };
    return { ok: true, report: data };
  } catch {
    return {
      ok: false,
      offline: true,
      error: "The detector isn't running. Start it with: python3 server.py",
    };
  }
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  // Only listen to our own extension's scripts.
  if (sender.id !== chrome.runtime.id || !msg || typeof msg !== "object") return;

  if (msg.type === "health") {
    health().then(sendResponse);
    return true; // tells Chrome we'll answer asynchronously
  }

  if (msg.type === "analyze") {
    // Analyze requests must come from a Gmail tab, and must be a sane size.
    if (!sender.url || !sender.url.startsWith("https://mail.google.com/")) return;
    if (typeof msg.raw !== "string" || msg.raw.length === 0 || msg.raw.length > MAX_EMAIL_SIZE) {
      sendResponse({ ok: false, error: "That email is empty or over the 10 MB limit." });
      return;
    }
    analyze(msg.raw).then(sendResponse);
    return true;
  }
});
