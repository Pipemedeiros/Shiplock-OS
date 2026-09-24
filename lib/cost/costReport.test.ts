import { describe, expect, it } from "vitest";
import { summarizeCost, parsePrices } from "../../scripts/cost-report.mjs";

// Q10: cost per first scan from receipts, with prices given on the command
// line, never hard-coded. Zero receipts means unavailable, not zero cost.
const r = (run: string, input: number, output: number, model = "claude-haiku-4-5", purpose = "first_scan") =>
  ({ purpose, model, input_tokens: input, output_tokens: output, audit_run_id: run });

describe("cost report", () => {
  it("parses prices per million tokens", () => {
    expect(parsePrices(["claude-haiku-4-5=1,5", "claude-sonnet-4-6=3,15"])).toEqual({
      "claude-haiku-4-5": { input: 1, output: 5 }, "claude-sonnet-4-6": { input: 3, output: 15 } });
    expect(() => parsePrices(["bad"])).toThrow();
  });
  it("summarizes first-scan tokens and dollars per run", () => {
    const out = summarizeCost([r("a", 1_000_000, 0), r("b", 2_000_000, 200_000), r("c", 0, 1_000_000), r("x", 5, 5, "m", "narrative")],
      { "claude-haiku-4-5": { input: 1, output: 5 } });
    expect(out.firstScan.runs).toBe(3);
    expect(out.firstScan.dollars).toEqual({ p50: 3, p95: 5, max: 5 });
    expect(out.firstScan.tokens?.max).toBe(2_200_000);
    expect(out.unpricedModels).toEqual(["m"]);
  });
  it("says unavailable for no receipts and lists models without a price", () => {
    expect(summarizeCost([], {}).firstScan).toEqual({ runs: 0, unavailable: true });
    expect(summarizeCost([r("a", 1, 1, "claude-opus-5")], {}).unpricedModels).toEqual(["claude-opus-5"]);
  });
});
