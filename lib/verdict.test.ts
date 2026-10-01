import { describe, expect, it } from "vitest";
import { verdictOf } from "./verdict";

const f = (severity: "CRITICAL" | "WARNING" | "INFO", confidence: "proven" | "corroborated" | "inferred" = "corroborated") => ({ severity, confidence });
const base = { audited: true, lastRunFailed: false, findings: [], unread: 0, blockedPrs: 0 };

// Felipe 2026-10-01: "easy for someone that doesn't understand security to
// know if they're cooked", without ever calling an app secure.
describe("verdict", () => {
  it("says exposed when a critical path is open, and how sure we are", () => {
    const v = verdictOf({ ...base, findings: [f("CRITICAL", "proven"), f("WARNING")] });
    expect(v).toMatchObject({ level: "exposed", word: "Exposed" });
    expect(v.plain).toMatch(/customer data/);
    expect(v.engineer).toMatch(/1 critical.*1 proven/);
  });

  it("says at risk for warnings only", () => {
    expect(verdictOf({ ...base, findings: [f("WARNING"), f("INFO")] })).toMatchObject({ level: "at_risk" });
  });

  it("an info finding alone is not at risk", () => {
    expect(verdictOf({ ...base, findings: [f("INFO")] })).toMatchObject({ level: "nothing_open" });
  });

  it("a pull request ShipLock blocked counts as at risk", () => {
    expect(verdictOf({ ...base, blockedPrs: 1 })).toMatchObject({ level: "at_risk" });
  });

  it("never says secure, and names what was not read", () => {
    const v = verdictOf({ ...base, unread: 3 });
    expect(v.level).toBe("nothing_open");
    expect(`${v.word} ${v.plain} ${v.engineer}`).not.toMatch(/secure|safe|clean|protected/i);
    expect(v.plain).toMatch(/3 areas/);
  });

  it("is unknown before the first audit or when the last one stopped", () => {
    expect(verdictOf({ ...base, audited: false })).toMatchObject({ level: "unknown", word: "Not audited yet" });
    expect(verdictOf({ ...base, lastRunFailed: true })).toMatchObject({ level: "unknown" });
  });

  it("keeps an earlier exposure visible even if the last run stopped", () => {
    expect(verdictOf({ ...base, lastRunFailed: true, findings: [f("CRITICAL")] })).toMatchObject({ level: "exposed" });
  });

  it("uses no dashes in customer copy", () => {
    for (const v of [verdictOf({ ...base, findings: [f("CRITICAL")] }), verdictOf(base), verdictOf({ ...base, audited: false })])
      expect(`${v.word}${v.plain}${v.engineer}`).not.toMatch(/[–—]/);
  });
});
