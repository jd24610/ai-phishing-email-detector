// Runs inside Gmail. Watches for emails you open, scans each one once,
// and shows a banner above it.
//
// Safety rules in this file:
// - Every piece of email text goes in with textContent, never innerHTML,
//   so a scam email can't inject code into the banner.
// - The banner lives in a CLOSED shadow root: Gmail's page (or anything
//   injected into it) can't reach in and change what we show you.
// - Nothing from the email is ever turned into a clickable link.
// - The raw email goes to our background worker, which only sends it
//   to 127.0.0.1. It never goes anywhere else.

(() => {
  const results = new Map();   // message ID -> report (so we don't re-scan)
  const inFlight = new Set();  // message IDs being scanned right now
  let autoScan = true;

  // ---------- settings ----------

  chrome.storage.local.get({ autoScan: true }, (s) => {
    autoScan = s.autoScan;
    if (autoScan) scheduleScan();
  });
  chrome.storage.onChanged.addListener((changes) => {
    if (changes.autoScan) {
      autoScan = changes.autoScan.newValue;
      if (autoScan) scheduleScan();
    }
  });

  // ---------- watching Gmail ----------

  // Gmail is a single-page app: opening an email doesn't load a new page,
  // it just changes the page. So we watch for changes, and wait a moment
  // for Gmail to finish (a "debounce") before looking.
  let timer = null;
  function scheduleScan() {
    clearTimeout(timer);
    timer = setTimeout(scanOpenMessages, 400);
  }
  new MutationObserver(() => autoScan && scheduleScan())
    .observe(document.body, { childList: true, subtree: true });

  function scanOpenMessages() {
    for (const { el, id } of PhishGmail.openMessages()) {
      if (el.querySelector("phish-detector-banner")) continue; // already showing
      if (results.has(id)) {
        showBanner(el, renderReport(results.get(id)));
      } else if (!inFlight.has(id)) {
        scan(el, id);
      }
    }
  }

  async function scan(el, id) {
    inFlight.add(id);
    showBanner(el, renderStatus("Checking this email for phishing..."));
    try {
      const { raw, tried } = await fetchOriginal(id);
      if (!raw) {
        // Show what we tried (formats and status codes only, never email content),
        // so a real-Gmail failure can be fixed without guessing.
        const summary = tried.map((t) => `${t.name}: ${t.result}`).join(" | ");
        console.warn("[Phishing Detector] Couldn't get the original email.", tried);
        return showBanner(el, renderStatus(
          `Couldn't read this email's original source. Tried: ${summary}`, true));
      }
      const answer = await chrome.runtime.sendMessage({ type: "analyze", raw });
      if (!answer || !answer.ok) {
        return showBanner(el, renderStatus(answer?.error || "Something went wrong.", true));
      }
      results.set(id, answer.report);
      showBanner(el, renderReport(answer.report));
    } catch {
      showBanner(el, renderStatus("Something went wrong while checking this email.", true));
    } finally {
      inFlight.delete(id);
    }
  }

  // Ask Gmail for the raw email, the same way its "Show original" menu does.
  // Same-site request, so your normal Gmail login is used. Nothing new is shared.
  // We try each known address format until one gives back a real email.
  let ik; // Gmail's account key, looked up once per page
  async function fetchOriginal(id) {
    if (ik === undefined) ik = PhishGmail.findIk();
    const tried = [];
    for (const { name, url } of PhishGmail.originalUrls(location.pathname, id, ik)) {
      try {
        const res = await fetch(url, { credentials: "same-origin" });
        const type = res.headers.get("content-type") || "";
        if (!res.ok) { tried.push({ name, result: `HTTP ${res.status}` }); continue; }
        if (!res.url.startsWith("https://mail.google.com/")) {
          tried.push({ name, result: "redirected away" }); continue;
        }
        const raw = PhishGmail.extractRaw(await res.text(), type);
        if (raw) return { raw, tried };
        tried.push({ name, result: `200 ${type.split(";")[0] || "?"}, no email found` });
      } catch {
        tried.push({ name, result: "network error" });
      }
    }
    if (!ik) tried.push({ name: "ik", result: "not found on page" });
    return { raw: null, tried };
  }

  // ---------- the banner ----------

  // Small helper: make an element with plain text in it.
  function el(tag, text, className) {
    const node = document.createElement(tag);
    if (text !== undefined) node.textContent = text;
    if (className) node.className = className;
    return node;
  }

  function showBanner(messageEl, content) {
    let host = messageEl.querySelector("phish-detector-banner");
    if (!host) {
      host = document.createElement("phish-detector-banner");
      host._root = host.attachShadow({ mode: "closed" });
      const anchor = PhishGmail.bannerAnchor(messageEl);
      anchor.parentElement.insertBefore(host, anchor);
    }
    const style = el("style", BANNER_CSS);
    host._root.replaceChildren(style, content);
  }

  function closeButton(box) {
    const btn = el("button", "×", "close");
    btn.title = "Hide";
    btn.setAttribute("aria-label", "Hide this banner");
    btn.addEventListener("click", () => { box.hidden = true; });
    return btn;
  }

  function renderStatus(message, isError = false) {
    const box = el("div", undefined, `box status ${isError ? "error" : ""}`);
    box.append(el("span", message), closeButton(box));
    return box;
  }

  function renderReport(r) {
    const level = { "Low risk": "low", "Suspicious": "mid", "Likely phishing": "high" }[r.verdict] || "mid";
    const box = el("div", undefined, `box ${level}`);

    const top = el("div", undefined, "top");
    const title = el("div");
    title.append(el("strong", r.verdict), el("span", ` · risk ${r.score}/100`, "score"));
    top.append(title, closeButton(box));
    box.append(top);

    if (level !== "low") {
      const list = el("ul");
      for (const f of r.top_reasons) list.append(el("li", f.message));
      box.append(list, el("p", r.advice, "advice"));
    } else {
      box.append(el("p", "No strong warning signs. Still double-check any request for money or passwords.", "advice"));
    }

    // Every finding, folded away until you want it.
    const more = el("details");
    more.append(el("summary", "All findings"));
    for (const cat of r.categories) {
      if (!cat.findings.length) continue;
      more.append(el("p", `${cat.name} (${cat.points} pts)`, "cat"));
      const ul = el("ul");
      for (const f of cat.findings) {
        const li = el("li");
        li.append(el("span", f.severity.toUpperCase(), `sev ${f.severity}`), el("span", f.message));
        ul.append(li);
      }
      more.append(ul);
    }
    box.append(more, el("p", "Checked on your computer by your local phishing detector.", "foot"));
    return box;
  }

  const BANNER_CSS = `
    :host { all: initial; display: block; margin: 8px 0 12px; }
    .box { font: 14px/1.45 Roboto, Arial, sans-serif; border-radius: 10px; padding: 12px 14px;
           border: 1px solid; color: #1c2430; }
    .low  { background: #e8f6ee; border-color: #b8e3c8; }
    .mid  { background: #fff4e0; border-color: #f2d39a; }
    .high { background: #fdecec; border-color: #f3b9b9; }
    .status { background: #f1f3f4; border-color: #dadce0; display: flex;
              justify-content: space-between; align-items: center; }
    .status.error { background: #fdecec; border-color: #f3b9b9; }
    .top { display: flex; justify-content: space-between; align-items: center; }
    .low strong { color: #1f8a4c; } .mid strong { color: #b26a00; } .high strong { color: #c62828; }
    strong { font-size: 15px; }
    .score { color: #5d6878; }
    ul { margin: 8px 0 4px; padding-left: 20px; } li { margin: 3px 0; }
    .advice { margin: 6px 0 0; }
    details { margin-top: 8px; } summary { cursor: pointer; color: #2f5bd3; }
    .cat { margin: 8px 0 0; font-weight: 600; }
    details ul { list-style: none; padding-left: 0; }
    details li { display: flex; gap: 8px; align-items: baseline; }
    .sev { flex: none; min-width: 58px; text-align: center; font-size: 10px; font-weight: 700;
           border-radius: 4px; padding: 1px 4px; background: #eef1f5; color: #5d6878; }
    .sev.high { background: #f9d6d6; color: #c62828; } .sev.medium { background: #fbe5bf; color: #8a5200; }
    .sev.info { background: #e3ebfb; color: #2f5bd3; }
    .foot { margin: 8px 0 0; font-size: 12px; color: #5d6878; }
    .close { border: 0; background: none; font-size: 20px; line-height: 1; cursor: pointer;
             color: #5d6878; padding: 0 2px; }
  `;
})();
