#!/usr/bin/env node
// Q33: no horizontal scroll on any public page, at phone and desktop width,
// with real device emulation (headless window sizes cannot go below ~500px).
// Usage: start the app (`npm run build && npx next start -p 3917`), start
// Chrome with `--headless=new --remote-debugging-port=9333`, then
// `node scripts/overflow-check.mjs`. Exits 1 if any page overflows.
// Signed-in dashboard pages need a session and are not covered here.
const pages = ["/", "/auth", "/onboarding", "/coverage", "/owasp", "/incidents", "/privacy", "/terms", "/cancelled", "/nope-404", "/accessibility"];
const list = await (await fetch("http://127.0.0.1:9333/json/list")).json();
const target = list.find((t) => t.type === "page");
const ws = new WebSocket(target.webSocketDebuggerUrl);
let id = 0; const pending = new Map(); let failed = false;
ws.onmessage = (m) => { const d = JSON.parse(m.data); if (d.id && pending.has(d.id)) { pending.get(d.id)(d); pending.delete(d.id); } };
await new Promise((r) => (ws.onopen = r));
const send = (method, params = {}) => new Promise((r) => { const i = ++id; pending.set(i, r); ws.send(JSON.stringify({ id: i, method, params })); });
await send("Page.enable"); await send("Runtime.enable");
for (const width of [390, 1280]) {
  await send("Emulation.setDeviceMetricsOverride", { width, height: 844, deviceScaleFactor: 2, mobile: width < 500 });
  for (const p of pages) {
    await send("Page.navigate", { url: `http://localhost:3917${p}` });
    await new Promise((r) => setTimeout(r, 1800));
    const res = await send("Runtime.evaluate", { returnByValue: true, expression: `(() => {
      const w = document.documentElement.clientWidth, sw = document.documentElement.scrollWidth;
      const wide = [...document.querySelectorAll("body *")].filter((e) => { const r = e.getBoundingClientRect(); return r.right > w + 1 && getComputedStyle(e).position !== "fixed"; })
        .slice(0, 4).map((e) => e.tagName.toLowerCase() + (e.className && typeof e.className === "string" ? "." + e.className.split(" ")[0] : "") + "(" + Math.round(e.getBoundingClientRect().right) + ")");
      return { url: location.pathname, w, sw, wide };
    })()` });
    const v = res.result.result.value;
    if (v.sw > v.w) failed = true;
    console.log(width, v.url, v.sw > v.w ? `OVERFLOW ${v.sw}>${v.w} ${v.wide.join(" ")}` : "ok");
  }
}
ws.close();
process.exitCode = failed ? 1 : 0;
