// Popup: detector status, the auto-scan switch, and (advanced) local server mode.

const statusEl = document.getElementById("status");
const help = document.getElementById("help");
const auto = document.getElementById("auto");
const server = document.getElementById("server");
const SERVER_ORIGIN = "http://127.0.0.1:8765/*";

function show(text, state, helpText = "") {
  statusEl.textContent = text;
  statusEl.className = `pill ${state}`;
  help.textContent = helpText;
  help.hidden = !helpText;
}

function refresh() {
  chrome.runtime.sendMessage({ type: "status" }, (res) => {
    if (!res) return show("Error", "down");
    if (res.engine === "server") {
      return res.ok
        ? show("Local server", "up")
        : show("Server not running", "down", "Start it on your computer: python3 server.py");
    }
    if (res.status === "ready") return show("Built-in, ready", "up");
    if (res.status === "loading") {
      show("Starting...", "", "Loading the built-in detector. This takes a few seconds the first time.");
      return setTimeout(refresh, 1000);
    }
    show("Built-in failed", "down", "The built-in detector couldn't start. Try reloading the extension.");
  });
}

chrome.storage.local.get({ autoScan: true, engine: "builtin" }, (s) => {
  auto.checked = s.autoScan;
  server.checked = s.engine === "server";
  refresh();
});

auto.addEventListener("change", () => chrome.storage.local.set({ autoScan: auto.checked }));

server.addEventListener("change", async () => {
  if (server.checked) {
    // Ask Chrome for permission to reach 127.0.0.1 only when it's needed.
    const granted = await chrome.permissions.request({ origins: [SERVER_ORIGIN] });
    if (!granted) { server.checked = false; return; }
  } else {
    await chrome.permissions.remove({ origins: [SERVER_ORIGIN] });
  }
  await chrome.storage.local.set({ engine: server.checked ? "server" : "builtin" });
  refresh();
});
