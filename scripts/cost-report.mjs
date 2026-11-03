// Cost per first scan from model usage receipts (migration
// 092). Local and read-only: pass a JSON file of receipt rows (for example
// the output of a read-only query Felipe runs) and prices per million tokens
// on the command line. No prices are hard-coded and nothing is fetched.
//
//   node scripts/cost-report.mjs receipts.json --price claude-haiku-4-5=1,5 --price claude-sonnet-4-6=3,15
//
// Zero first-scan receipts means "unavailable", never zero cost.
import { readFile } from "node:fs/promises";
import { pathToFileURL } from "node:url";

/** Parses model=input,output prices per million tokens. */
export function parsePrices(values) {
  const prices = {};
  for (const value of values) {
    const match = /^([^=\s]+)=(\d+(?:\.\d+)?),(\d+(?:\.\d+)?)$/.exec(value);
    if (!match) throw new Error(`Price must look like model=input,output per million tokens: ${value}`);
    prices[match[1]] = { input: Number(match[2]), output: Number(match[3]) };
  }
  return prices;
}

const pct = (sorted, p) => sorted[Math.min(sorted.length - 1, Math.ceil(p * sorted.length) - 1)];
const round = (n) => Math.round(n * 10_000) / 10_000;

/** Cost per first scan from model usage receipts; unpriced models are listed,
 * not guessed. */
export function summarizeCost(receipts, prices) {
  const unpriced = new Set();
  const perRun = new Map();
  for (const r of receipts) {
    if (!prices[r.model]) unpriced.add(r.model);
    if (r.purpose !== "first_scan" || !r.audit_run_id) continue;
    const price = prices[r.model];
    const run = perRun.get(r.audit_run_id) ?? { tokens: 0, dollars: 0, priced: true };
    run.tokens += r.input_tokens + r.output_tokens;
    if (price) run.dollars += (r.input_tokens * price.input + r.output_tokens * price.output) / 1_000_000;
    else run.priced = false;
    perRun.set(r.audit_run_id, run);
  }
  const runs = [...perRun.values()];
  if (runs.length === 0) return { firstScan: { runs: 0, unavailable: true }, unpricedModels: [...unpriced].sort() };
  const tokens = runs.map((r) => r.tokens).sort((a, b) => a - b);
  const priced = runs.filter((r) => r.priced).map((r) => r.dollars).sort((a, b) => a - b);
  return {
    firstScan: {
      runs: runs.length,
      tokens: { p50: pct(tokens, 0.5), p95: pct(tokens, 0.95), max: tokens[tokens.length - 1] },
      dollars: priced.length ? { p50: round(pct(priced, 0.5)), p95: round(pct(priced, 0.95)), max: round(priced[priced.length - 1]) } : null,
      unpricedRuns: runs.length - priced.length,
    },
    unpricedModels: [...unpriced].sort(),
  };
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  const args = process.argv.slice(2);
  const file = args.find((a, i) => !a.startsWith("--") && args[i - 1] !== "--price");
  const prices = parsePrices(args.filter((_, i) => args[i - 1] === "--price"));
  if (!file) throw new Error("Pass a JSON file of receipt rows.");
  console.log(JSON.stringify(summarizeCost(JSON.parse(await readFile(file, "utf8")), prices), null, 2));
}
