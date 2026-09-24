import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

// ShipLock-funded model calls are a cost and a contract boundary (AGENTS.md:
// one bounded first scan per account; afterwards the customer funds AI). Every
// place that builds a model client must be listed here with the reason it may
// spend, so a new unbounded, ShipLock-keyed route cannot land unnoticed. The
// 2026-09-23 removal of /api/deep/github/reason (a signed-in POST that spent
// ShipLock's key with no bound) is why this exists.
const ALLOWED: Record<string, string> = {
  "lib/agent/attack.ts": "audit hypotheses; called only when the first-scan credit is claimed (3G-1)",
  "lib/analyzer.ts": "legacy scan report; off unless SHIPLOCK_FUNDED_SCAN_REPORT=true (3G-2)",
  "lib/graph/narrative.ts": "graph narrative; off unless SHIPLOCK_FUNDED_NARRATIVES=true (3G-2)",
  "lib/graph/defender.ts": "unused per AGENTS.md; must not gain a caller without a bound",
  "lib/proving/agent.ts": "proving ground; not launch-proven per AGENTS.md",
  "lib/intelligence/apiMode.ts": "customer-funded: explicit customer key only, never ShipLock's",
};

function sources(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) return sources(path);
    return /\.(ts|tsx|mjs)$/.test(name) && !/\.test\./.test(name) ? [path] : [];
  });
}

describe("model clients are an allowlisted, reviewed set", () => {
  it("only the listed files construct an Anthropic client", () => {
    const found = ["lib", "app"].flatMap(sources).filter((file) => /new Anthropic\(/.test(readFileSync(file, "utf8")));
    expect(found.sort()).toEqual(Object.keys(ALLOWED).sort());
  });

  it("the customer-funded path never falls back to ShipLock's environment key", () => {
    const code = readFileSync("lib/intelligence/apiMode.ts", "utf8");
    expect(code).toMatch(/new Anthropic\(\{ apiKey: credential\.apiKey/);
    expect(code).not.toMatch(/ANTHROPIC_API_KEY\b(?![^\n]*environment)/);
  });

  // Q10: cost per run must be measurable, so each model client's response
  // leaves a usage receipt, in the client or the caller that owns the run.
  // `defender.ts` has no caller; `proving/agent.ts` records with the Q6 worker.
  const RECEIPT_OWNER: Record<string, string | null> = {
    "lib/agent/attack.ts": "lib/agent/audit.ts",
    "lib/analyzer.ts": "lib/analyzer.ts",
    "lib/graph/narrative.ts": "lib/graph/graphRun.ts",
    "lib/intelligence/apiMode.ts": "lib/intelligence/apiMode.ts",
    "lib/graph/defender.ts": null,
    "lib/proving/agent.ts": null,
  };
  it("every model client's usage is receipted by it or its run owner", () => {
    expect(Object.keys(RECEIPT_OWNER).sort()).toEqual(Object.keys(ALLOWED).sort());
    for (const [client, owner] of Object.entries(RECEIPT_OWNER)) {
      if (!owner) continue;
      expect({ client, records: /\brecordModelUsage\(/.test(readFileSync(owner, "utf8")) }).toEqual({ client, records: true });
    }
  });
});
