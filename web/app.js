// Front end for the local phishing detector.
//
// SECURITY NOTE: every piece of text from the email (subject, sender,
// findings) is inserted with textContent, never innerHTML. A phishing
// email could have a subject like <img src=x onerror=...>. With
// textContent it just shows up as harmless text instead of running.

const MAX_SIZE = 10 * 1024 * 1024;

const $ = (id) => document.getElementById(id);
const drop = $("drop");
const fileInput = $("file");
const statusEl = $("status");

// Build an element with plain text inside. The only way we add content.
function el(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (className) node.className = className;
  return node;
}

function setStatus(message, isError = false) {
  statusEl.textContent = message;
  statusEl.classList.toggle("error", isError);
}

async function analyze(file) {
  $("result").hidden = true;
  if (!file) return;
  if (file.size > MAX_SIZE) return setStatus("That file is over the 10 MB limit.", true);
  if (file.size === 0) return setStatus("That file is empty.", true);

  setStatus(`Checking ${file.name}...`);
  try {
    const response = await fetch("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "message/rfc822" },
      body: await file.arrayBuffer(),
    });
    const data = await response.json();
    if (!response.ok) return setStatus(data.error || "Something went wrong.", true);
    setStatus("");
    render(data);
  } catch {
    setStatus("Couldn't reach the detector. Is server.py still running?", true);
  }
}

function render(data) {
  const level = { "Low risk": "low", "Suspicious": "mid", "Likely phishing": "high" }[data.verdict];
  $("verdict").className = `verdict ${level}`;
  $("verdict-text").textContent = data.verdict;
  $("score-num").textContent = data.score;
  $("bar-fill").style.width = `${data.score}%`;
  $("bar-fill").className = level;

  const e = data.email;
  $("from").textContent = e.from_name ? `${e.from_name} <${e.from_address}>` : e.from_address;
  $("subject").textContent = e.subject || "(no subject)";
  $("auth").textContent =
    `SPF ${data.auth.spf} · DKIM ${data.auth.dkim} · DMARC ${data.auth.dmarc} · ` +
    `${e.links} link${e.links === 1 ? "" : "s"} · ` +
    `${e.attachments} attachment${e.attachments === 1 ? "" : "s"}`;

  // On a low-risk email, weak clues aren't "reasons". Call them what they are.
  $("reasons-title").textContent = level === "low" ? "Minor notes" : "Top reasons";
  const reasons = $("reasons");
  reasons.replaceChildren();
  if (data.top_reasons.length === 0) reasons.append(el("li", "No warning signs found."));
  for (const f of data.top_reasons) reasons.append(el("li", f.message));

  $("advice").textContent = data.advice;

  const cats = $("categories");
  cats.replaceChildren();
  for (const cat of data.categories) {
    const box = el("details", undefined, "cat");
    const serious = cat.findings.some((f) => f.severity === "high" || f.severity === "medium");
    if (serious) box.open = true;

    const summary = el("summary");
    summary.append(el("span", cat.name), el("span", `${cat.points} pts`, "pts"));
    box.append(summary);

    if (cat.findings.length === 0) box.append(el("p", "Nothing found.", "none"));
    const list = el("ul");
    for (const f of cat.findings) {
      const item = el("li");
      item.append(el("span", f.severity.toUpperCase(), `sev ${f.severity}`), el("span", f.message));
      list.append(item);
    }
    box.append(list);
    cats.append(box);
  }

  const notes = $("notes");
  notes.replaceChildren(...data.notes.map((n) => el("li", n)));

  $("result").hidden = false;
}

// File picker
fileInput.addEventListener("change", () => analyze(fileInput.files[0]));

// Drag and drop
for (const evt of ["dragenter", "dragover"]) {
  drop.addEventListener(evt, (e) => { e.preventDefault(); drop.classList.add("over"); });
}
for (const evt of ["dragleave", "drop"]) {
  drop.addEventListener(evt, (e) => { e.preventDefault(); drop.classList.remove("over"); });
}
drop.addEventListener("drop", (e) => analyze(e.dataTransfer.files[0]));
