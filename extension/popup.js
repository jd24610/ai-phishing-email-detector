// Popup: shows whether the local detector is running, and the auto-scan switch.

const server = document.getElementById("server");
const help = document.getElementById("help");
const auto = document.getElementById("auto");

chrome.runtime.sendMessage({ type: "health" }, (res) => {
  const up = Boolean(res && res.ok);
  server.textContent = up ? "Running" : "Not running";
  server.className = `pill ${up ? "up" : "down"}`;
  help.hidden = up;
});

chrome.storage.local.get({ autoScan: true }, (s) => { auto.checked = s.autoScan; });
auto.addEventListener("change", () => chrome.storage.local.set({ autoScan: auto.checked }));
