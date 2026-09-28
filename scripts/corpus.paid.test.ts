import { spawnSync } from "node:child_process";
import { createRequire } from "node:module";
import { describe, expect, it } from "vitest";

// Q11: the corpus harness's paid mode. It spends ShipLock's key, so it must
// refuse before any call unless Felipe's confirmation, a dollar cap and a
// price for every planned model are given, and the worst case fits the cap.
const require = createRequire(import.meta.url);
type Plan = { id: string; model: string; inputChars: number; maxTokens: number };
const { paidPlan } = require("./corpus.cjs") as {
  paidPlan: (plans: Plan[], prices: Record<string, { input: number; output: number }>, maxUsd: number) =>
    { ok: boolean; reason?: string; worstCaseUsd: number | null; rows: (Plan & { worstCaseUsd: number })[] };
};

const prices = { "claude-sonnet-4-6": { input: 3, output: 15 }, "claude-haiku-4-5": { input: 1, output: 5 } };
const plans = [
  { id: "big", model: "claude-sonnet-4-6", inputChars: 20_000, maxTokens: 13_200 },
  { id: "small", model: "claude-haiku-4-5-20251001", inputChars: 4_000, maxTokens: 4_000 },
];

describe("paidPlan", () => {
  it("bounds each call by its whole output cap and a generous input bound, and fits the cap", () => {
    const plan = paidPlan(plans, prices, 1);
    // input bound = chars / 2 tokens: 10,000 and 2,000
    const expected = (10_000 * 3 + 13_200 * 15 + 2_000 * 1 + 4_000 * 5) / 1_000_000;
    expect(plan.ok).toBe(true);
    expect(plan.worstCaseUsd).toBeCloseTo(expected, 6);
    expect(plan.rows.map((r) => r.id)).toEqual(["big", "small"]);
  });

  it("refuses when the worst case exceeds the cap", () => {
    const plan = paidPlan(plans, prices, 0.1);
    expect(plan.ok).toBe(false);
    expect(plan.reason).toMatch(/exceeds the cap/);
  });

  it("refuses when a planned model has no price (dated ids match their undated price)", () => {
    const plan = paidPlan(plans, { "claude-sonnet-4-6": prices["claude-sonnet-4-6"] }, 1);
    expect(plan.ok).toBe(false);
    expect(plan.reason).toMatch(/claude-haiku-4-5-20251001/);
  });
});

describe("corpus manifest selection (Q23)", () => {
  const load = (env: Record<string, string>) => spawnSync(process.execPath,
    ["-e", "console.log(require('./scripts/corpus.cjs').manifest.experiment)"], { encoding: "utf8", env: { ...process.env, ...env } });
  it("reads docs/CORPUS.json by default and another manifest when SHIPLOCK_CORPUS names one", () => {
    const base = load({}).stdout.trim();
    expect(base).toBe(JSON.parse(require("node:fs").readFileSync("docs/CORPUS.json", "utf8")).experiment);
    const dir = require("node:fs").mkdtempSync(require("node:path").join(require("node:os").tmpdir(), "corpus-"));
    const alt = require("node:path").join(dir, "alt.json");
    require("node:fs").writeFileSync(alt, JSON.stringify({ version: 1, experiment: "alt-corpus", prediction: "x", repositories: [], labels: [] }));
    expect(load({ SHIPLOCK_CORPUS: alt }).stdout.trim()).toBe("alt-corpus");
  });
});

describe("corpus.cjs paid CLI refuses before spending", () => {
  const run = (...args: string[]) => spawnSync(process.execPath, ["scripts/corpus.cjs", "paid", ...args], {
    encoding: "utf8", env: { ...process.env, ANTHROPIC_API_KEY: "sk-test-not-used" } });

  it("without --confirm-paid", () => {
    const r = run("--max-usd", "1", "--price", "claude-sonnet-4-6=3,15");
    expect(r.status).not.toBe(0);
    expect(r.stderr).toMatch(/--confirm-paid/);
  });

  it("with --only naming no pinned repository", () => {
    const r = run("--confirm-paid", "--max-usd", "1", "--price", "claude-sonnet-5=2,10", "--model", "claude-sonnet-5", "--only", "nope");
    expect(r.status).not.toBe(0);
    expect(r.stderr).toMatch(/--only nope/);
  }, 120_000);

  it("without a dollar cap", () => {
    const r = run("--confirm-paid", "--price", "claude-sonnet-4-6=3,15");
    expect(r.status).not.toBe(0);
    expect(r.stderr).toMatch(/--max-usd/);
  });
});
