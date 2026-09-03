import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";

/**
 * THE FACT-LAYER INVARIANT, ENFORCED MECHANICALLY.
 *
 * A boolean in the fact layer may not be read as evidence of ABSENCE unless it
 * has a paired readability field AND the reading site checks that pair.
 *
 * Both clauses earn their place from a real bug:
 *
 *   clause 1  ownershipFiltered had no pair, so "we could not see the scoping"
 *             and "there is no scoping" were the same value. Seven of
 *             corpus-b's eight reasoned criticals came from that.
 *
 *   clause 2  stack.tools DID have a pair -- databaseUnknown -- and
 *             findings.ts simply never read it. A census that only asks "does a
 *             pair exist" is structurally blind to this, and it missed four
 *             more: attackPaths' service-role path, routeRisk, the prompt's
 *             `unscoped` label, and a claim marked `verified: true`.
 *
 * WHAT THIS TEST CANNOT DO, stated so nobody trusts it further than it goes.
 * It is a source-text check, not a type or dataflow analysis. It cannot see a
 * fact copied into a local variable and negated later, a fact reached through a
 * helper, or a fact consumed in a file not listed in CRITICAL_PATH. It catches
 * the shape every one of these bugs actually had -- `!route.field` or
 * `field ? … : …` in a decision file -- and nothing subtler. The `as RouteFact`
 * fixtures in the test suite are outside it entirely, and one of those silently
 * changed a ranking during this very stage.
 */

// Comments are BLANKED, not removed, so line indices still map to the file.
const read = (p: string) =>
  readFileSync(p, "utf8")
    .replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, " "))
    .replace(/^(\s*)\/\/.*$/gm, "$1");

/** Fact -> the readability field that must be consulted alongside it. */
const PAIRS: Record<string, string> = {
  authenticated: "identityReadable",
  machineGated: "identityReadable",
  ownershipFiltered: "ownershipReadable",
  usesServiceRole: "serviceRoleReadable",
};

/**
 * Files where a fact becomes a customer-facing claim: attack paths, prompt
 * construction, severity, and confidence. Adding a decision file here is
 * deliberate; forgetting to is what this test exists to punish.
 */
const CRITICAL_PATH = [
  "lib/graph/attackPaths.ts",
  "lib/agent/attack.ts",
  "lib/agent/findings.ts",
  "lib/agent/diffScan.ts",
  "lib/graph/routeChecks.ts",
];

/** A line that reads a fact as absence: `!x.field`, or `x.field ? a : b`. */
function absenceReads(src: string, fact: string): number[] {
  const lines = src.split("\n");
  const hits: number[] = [];
  const neg = new RegExp(`!\\s*\\w+[!.]?\\.${fact}\\b`);
  const tern = new RegExp(`\\w+[!.]?\\.${fact}\\s*\\?`);
  lines.forEach((l, i) => {
    if (neg.test(l) || tern.test(l)) hits.push(i);
  });
  return hits;
}

/** The readability pair, mentioned anywhere in the same statement-ish window. */
function pairNearby(src: string, line: number, pair: string): boolean {
  const lines = src.split("\n");
  const window = lines.slice(Math.max(0, line - 12), line + 12).join("\n");
  return new RegExp(`\\b${pair}\\b`).test(window);
}

describe("fact-layer invariant", () => {
  it("declares a readability pair for every fact read as absence", () => {
    // Clause 1. If a new boolean joins RouteFact and a critical-path file starts
    // reading `!route.newField`, it must appear in PAIRS first.
    const inventory = read("lib/graph/routeInventory.ts");
    const declared = [...inventory.matchAll(/^\s{2}(\w+): boolean;/gm)].map((m) => m[1]);
    const readabilityFields = declared.filter((f) => /Readable$/.test(f));
    expect(readabilityFields.length).toBeGreaterThan(0);

    const unpaired: string[] = [];
    for (const file of CRITICAL_PATH) {
      const src = read(file);
      for (const fact of declared) {
        if (/Readable$/.test(fact)) continue;
        if (PAIRS[fact]) continue;
        if (absenceReads(src, fact).length > 0) unpaired.push(`${file}: !route.${fact}`);
      }
    }
    expect(unpaired, `fact read as absence with no declared pair:\n${unpaired.join("\n")}`).toEqual([]);
  });

  it("checks the pair at every site that reads a fact as absence", () => {
    // Clause 2. The one stage 2 proved a census cannot catch.
    const unread: string[] = [];
    for (const file of CRITICAL_PATH) {
      const src = read(file);
      for (const [fact, pair] of Object.entries(PAIRS)) {
        for (const line of absenceReads(src, fact)) {
          if (!pairNearby(src, line, pair)) {
            unread.push(
              `${file}:${line + 1} reads ${fact} as absence without ${pair}\n      ${src.split("\n")[line].trim()}`,
            );
          }
        }
      }
    }
    expect(unread, `absence read without its readability pair:\n${unread.join("\n")}`).toEqual([]);
  });

  it("fails when a pair is removed — proving it is not vacuous", () => {
    // A test that passes because it checks nothing is worse than no test, so
    // this asserts the detector fires on a deliberately broken sample.
    const broken = `if (route.authenticated && !route.ownershipFiltered) { report(); }`;
    expect(absenceReads(broken, "ownershipFiltered")).toHaveLength(1);
    expect(pairNearby(broken, 0, "ownershipReadable")).toBe(false);
  });

  it("recognises a correctly guarded site", () => {
    const good = `if (route.ownershipReadable && !route.ownershipFiltered) { report(); }`;
    expect(pairNearby(good, 0, "ownershipReadable")).toBe(true);
  });
});
