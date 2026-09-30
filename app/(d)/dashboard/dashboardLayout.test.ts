import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

// Felipe (2026-09-30): text ran outside its box on Risks and Activity (long
// routes and file paths have no break points), and he dislikes the "Watching"
// badge and green dots. Green also reads as "clean", which an audit never is.
const css = readFileSync("app/(d)/v3.css", "utf8");
const rule = (selector: string) => css.match(new RegExp(`(^|\\n)${selector.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\s*\\{([^}]*)\\}`))?.[2] ?? "";

describe("dashboard layout", () => {
  it("wraps long paths inside their boxes", () => {
    expect(rule(".v3-chain-step")).toMatch(/min-width:\s*0/);
    expect(rule(".v3-node")).toMatch(/overflow-wrap:\s*anywhere/);
    expect(rule(".v3-risk p")).toMatch(/overflow-wrap:\s*anywhere/);
    expect(rule(".v3-trace-line")).toMatch(/overflow-wrap:\s*anywhere/);
  });

  it("has no Watching badge and no green dot for a run that found nothing", () => {
    expect(readFileSync("app/(d)/dashboard/layout.tsx", "utf8")).not.toMatch(/Watching|v3-dot live/);
    expect(readFileSync("app/(d)/dashboard/page.tsx", "utf8")).not.toMatch(/var\(--ok\)/);
    expect(readFileSync("components/v3/RunList.tsx", "utf8")).not.toMatch(/var\(--ok\)/);
  });
});
