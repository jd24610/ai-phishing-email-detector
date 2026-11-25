// The built-in detector: runs our Python code inside Chrome with Pyodide.
//
// Pyodide is Python compiled to WebAssembly. It's bundled inside the
// extension (extension/pyodide/), so nothing is downloaded at run time
// and no email ever leaves this computer.
//
// This runs in a Web Worker, so the heavy work never slows down Gmail.

import { loadPyodide } from "./pyodide/pyodide.mjs";

const here = (path) => new URL(path, import.meta.url).href;

// Start loading right away. The first load takes a couple of seconds;
// after that, each email takes a fraction of a second.
const ready = (async () => {
  const started = performance.now();
  const pyodide = await loadPyodide({ indexURL: here("./pyodide/") });

  // Copy our detector's Python files into Pyodide's in-memory file system.
  const files = await (await fetch(here("./py/files.json"))).json();
  for (const { path } of files) {
    const data = new Uint8Array(await (await fetch(here(`./py/${path}`))).arrayBuffer());
    pyodide.FS.mkdirTree("/app/" + path.split("/").slice(0, -1).join("/"));
    pyodide.FS.writeFile("/app/" + path, data);
  }
  pyodide.runPython(`
import sys
sys.path.insert(0, "/app")
from detector.report import analyze_raw_to_json
`);
  const analyze = pyodide.globals.get("analyze_raw_to_json");
  return { analyze, loadMs: Math.round(performance.now() - started) };
})();

let status = "loading";
ready.then(() => { status = "ready"; }, () => { status = "failed"; });

self.onmessage = async (event) => {
  const { id, type, raw } = event.data || {};
  try {
    if (type === "status") {
      const info = status === "ready" ? await ready : null;
      return self.postMessage({ id, ok: true, status, loadMs: info?.loadMs });
    }
    if (type === "analyze") {
      const { analyze } = await ready;
      const json = analyze(raw);          // calls our Python function directly
      const report = JSON.parse(json);
      if (report.error) return self.postMessage({ id, ok: false, error: report.error });
      return self.postMessage({ id, ok: true, report });
    }
    self.postMessage({ id, ok: false, error: "Unknown request." });
  } catch (err) {
    // Python errors can include file paths; keep the message short.
    console.error("[Phishing Detector] engine error", err);
    self.postMessage({ id, ok: false, error: "The built-in detector hit an error on this email." });
  }
};
