// Hidden "offscreen" page.
//
// Why does this exist? Chrome's background service worker can't run
// Pyodide (it isn't allowed to load extra scripts after it starts, and
// Chrome shuts it down when idle). An offscreen page stays alive and can
// start a normal Web Worker, so that's where the detector lives.
//
// This page just passes messages: background.js <-> engine-worker.js.

const worker = new Worker("engine-worker.js", { type: "module" });
const pending = new Map();
let nextId = 1;

worker.onmessage = (event) => {
  const { id, ...result } = event.data;
  const resolve = pending.get(id);
  if (resolve) {
    pending.delete(id);
    resolve(result);
  }
};

function ask(message) {
  return new Promise((resolve) => {
    const id = nextId++;
    pending.set(id, resolve);
    worker.postMessage({ id, ...message });
  });
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  // Only our own background worker talks to this page.
  if (sender.id !== chrome.runtime.id || !msg || msg.target !== "offscreen") return;
  if (msg.type === "status") {
    ask({ type: "status" }).then(sendResponse);
    return true;
  }
  if (msg.type === "analyze" && typeof msg.raw === "string") {
    ask({ type: "analyze", raw: msg.raw }).then(sendResponse);
    return true;
  }
});
