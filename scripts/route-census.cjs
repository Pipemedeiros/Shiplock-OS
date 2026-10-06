#!/usr/bin/env node
/* eslint-disable @typescript-eslint/no-require-imports -- Node-only CJS runner reusing the corpus harness loader, like scripts/corpus.cjs. */
// Route identity census over the pinned corpora, offline (AGENTS.md: freeze
// the affected route census before changing a security fact). Reuses the
// corpus harness's own loader and archive pinning; no network, no model.
//
//   node scripts/route-census.cjs <out.json>             one census
//   node scripts/route-census.cjs --diff <a.json> <b.json>  routes whose state moved
//
// Each route's state: machine | user | unreadable | anonymous, with scoped
// and data flags. Output is bounded: paths and states only, never source.
const fs = require("node:fs");
const path = require("node:path");
const { execFileSync } = require("node:child_process");

const MANIFESTS = ["docs/CORPUS.json", "docs/CORPUS-2.json", "docs/CORPUS-3.json", "docs/CORPUS-4.json"];
const root = path.resolve(__dirname, "..");

function stateOf(r) {
  if (r.machineGated) return "machine";
  if (r.authenticated) return "user";
  if (!r.identityReadable) return "unreadable";
  return "anonymous";
}

async function censusOne(manifest) {
  // The harness reads its manifest at load time, so each corpus loads fresh.
  process.env.SHIPLOCK_CORPUS = manifest;
  for (const key of Object.keys(require.cache)) if (key.endsWith(path.join("scripts", "corpus.cjs"))) delete require.cache[key];
  const corpus = require("./corpus.cjs");
  const product = corpus.loadProductModules();
  const out = {};
  for (const pin of corpus.manifest.repositories) {
    const { routes } = await corpus.analyzePin(product, pin);
    out[pin.id] = Object.fromEntries(routes.map((r) => [r.path,
      `${stateOf(r)}${r.ownershipFiltered ? "+scoped" : ""}${r.tables.length ? "+data" : ""}`]));
  }
  return out;
}

async function main() {
  const [mode, a, b] = process.argv.slice(2);
  if (mode === "--diff") {
    const before = JSON.parse(fs.readFileSync(a, "utf8")).repositories, after = JSON.parse(fs.readFileSync(b, "utf8")).repositories;
    const moved = [];
    for (const repo of Object.keys({ ...before, ...after })) {
      const x = before[repo] ?? {}, y = after[repo] ?? {};
      for (const route of new Set([...Object.keys(x), ...Object.keys(y)])) {
        if (x[route] !== y[route]) moved.push({ repo, route, before: x[route] ?? null, after: y[route] ?? null });
      }
    }
    console.log(JSON.stringify({ moved: moved.length, routes: moved }, null, 1));
    return;
  }
  if (!mode) throw new Error("usage: route-census.cjs <out.json> | --diff <a> <b>");
  const repositories = {};
  for (const manifest of MANIFESTS) Object.assign(repositories, await censusOne(manifest));
  const states = {};
  for (const routes of Object.values(repositories)) for (const s of Object.values(routes)) {
    const k = s.split("+")[0]; states[k] = (states[k] ?? 0) + 1;
  }
  const result = { capturedAt: new Date().toISOString(),
    head: execFileSync("git", ["rev-parse", "HEAD"], { cwd: root, encoding: "utf8" }).trim(),
    dirtyTree: execFileSync("git", ["status", "--porcelain"], { cwd: root, encoding: "utf8" }).trim().length > 0,
    manifests: MANIFESTS, totals: states, repositories };
  fs.writeFileSync(mode, JSON.stringify(result) + "\n", { flag: "wx" });
  console.log(JSON.stringify({ repositories: Object.keys(repositories).length, totals: states }));
}
main().catch((error) => { console.error(error.stack ?? error.message); process.exitCode = 1; });
