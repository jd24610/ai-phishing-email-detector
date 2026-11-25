// Background service worker: the traffic cop.
//
// Gmail tab (content.js) --raw email--> here --> detector --> verdict back.
//
// Two detectors are possible:
//   "builtin" (default): Python running inside Chrome via Pyodide.
//                        Nothing to install, nothing leaves the computer.
//   "server":            the local server (python3 server.py) on 127.0.0.1.
//                        Optional, mostly for development.

const API = "http://127.0.0.1:8765";
const SERVER_ORIGIN = "http://127.0.0.1:8765/*";
const MAX_EMAIL_SIZE = 10 * 1024 * 1024;

async function getEngine() {
  const { engine } = await chrome.storage.local.get({ engine: "builtin" });
  return engine === "server" ? "server" : "builtin";
}

// ---------- built-in detector ----------

let creating = null;
async function ensureOffscreen() {
  const existing = await chrome.runtime.getContexts({ contextTypes: ["OFFSCREEN_DOCUMENT"] });
  if (existing.length) return;
  creating ||= chrome.offscreen.createDocument({
    url: "offscreen.html",
    reasons: ["WORKERS"],
    justification: "Runs the phishing detector (Python compiled to WebAssembly) in a worker, entirely on this computer.",
  }).finally(() => { creating = null; });
  await creating;
}

async function builtinAsk(message) {
  await ensureOffscreen();
  const answer = await chrome.runtime.sendMessage({ target: "offscreen", ...message });
  return answer || { ok: false, error: "The built-in detector didn't answer." };
}

// ---------- optional local server ----------

async function serverHealth() {
  try {
    const res = await fetch(`${API}/api/health`, { cache: "no-store" });
    return { ok: res.ok };
  } catch {
    return { ok: false };
  }
}

async function serverAnalyze(raw) {
  if (!(await chrome.permissions.contains({ origins: [SERVER_ORIGIN] }))) {
    return { ok: false, error: "Local server mode needs permission. Turn it on again from the toolbar icon." };
  }
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
    return { ok: false, offline: true, error: "The local server isn't running. Start it with: python3 server.py" };
  }
}

// ---------- messages ----------

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  // Only listen to our own extension's scripts, and never to offscreen traffic.
  if (sender.id !== chrome.runtime.id || !msg || typeof msg !== "object" || msg.target) return;

  if (msg.type === "status") {
    (async () => {
      const engine = await getEngine();
      if (engine === "server") return { engine, ...(await serverHealth()) };
      const s = await builtinAsk({ type: "status" });
      return { engine, ok: s.ok && s.status !== "failed", status: s.status, loadMs: s.loadMs };
    })().then(sendResponse);
    return true;
  }

  if (msg.type === "warmup") {
    // Gmail opened: start loading the built-in detector early so the
    // first email is fast.
    getEngine().then((engine) => engine === "builtin" && ensureOffscreen());
    return;
  }

  if (msg.type === "analyze") {
    // Analyze requests must come from a Gmail tab, and must be a sane size.
    if (!sender.url || !sender.url.startsWith("https://mail.google.com/")) return;
    if (typeof msg.raw !== "string" || msg.raw.length === 0 || msg.raw.length > MAX_EMAIL_SIZE) {
      sendResponse({ ok: false, error: "That email is empty or over the 10 MB limit." });
      return;
    }
    getEngine()
      .then((engine) => (engine === "server" ? serverAnalyze(msg.raw) : builtinAsk({ type: "analyze", raw: msg.raw })))
      .then(sendResponse);
    return true;
  }
});
