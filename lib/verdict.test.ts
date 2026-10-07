import { describe, expect, it } from "vitest";
import { auditState, verdictOf } from "./verdict";

const f = (severity: "CRITICAL" | "WARNING" | "INFO", confidence: "proven" | "corroborated" | "inferred" = "corroborated") => ({ severity, confidence });
const base = { audited: true, lastRunFailed: false, findings: [], unread: 0, blockedPrs: 0 };

// Felipe 2026-10-01: a status anyone can read, in Stripe/Supabase product
// copy, without ever calling an app secure.
describe("verdict", () => {
  it("says exposed when a critical issue is open", () => {
    expect(verdictOf({ ...base, findings: [f("CRITICAL", "proven"), f("WARNING")] }))
      .toEqual({ level: "exposed", word: "Exposed", summary: "1 critical issue exposes customer data." });
    expect(verdictOf({ ...base, findings: [f("CRITICAL"), f("CRITICAL")] }).summary).toBe("2 critical issues expose customer data.");
  });

  it("says at risk for warnings or a blocked pull request", () => {
    expect(verdictOf({ ...base, findings: [f("WARNING"), f("WARNING")] })).toEqual({ level: "at_risk", word: "At risk", summary: "2 warnings need review." });
    expect(verdictOf({ ...base, blockedPrs: 1 })).toMatchObject({ level: "at_risk", summary: "1 pull request was blocked." });
  });

  it("an info issue alone is not at risk", () => {
    expect(verdictOf({ ...base, findings: [f("INFO")] })).toMatchObject({ level: "clear" });
  });

  it("never says secure, and says what was not checked", () => {
    const v = verdictOf({ ...base, unread: 3 });
    expect(v).toEqual({ level: "clear", word: "No open issues", summary: "3 areas were not checked." });
    expect(`${v.word} ${v.summary}`).not.toMatch(/secure|safe|clean|protected/i);
    expect(verdictOf(base).summary).toBe("In the code this audit read.");
  });

  // A1 (Felipe 2026-10-07): only confirmed issues set the status; the rest
  // is named as candidates to review, never counted as an issue.
  it("names what is left to review without calling it an issue", () => {
    expect(verdictOf({ ...base, toReview: 4 })).toEqual({ level: "clear", word: "No open issues", summary: "4 candidates to review." });
    expect(verdictOf({ ...base, toReview: 1, unread: 2 }).summary).toBe("1 candidate to review. 2 areas were not checked.");
  });

  it("is unknown before the first audit or when the last one stopped", () => {
    expect(verdictOf({ ...base, audited: false })).toEqual({ level: "unknown", word: "Not audited", summary: "Run an audit to see your status." });
    expect(verdictOf({ ...base, lastRunFailed: true })).toEqual({ level: "unknown", word: "Unknown", summary: "The last audit did not finish." });
  });

  it("keeps an earlier exposure visible even if the last run stopped", () => {
    expect(verdictOf({ ...base, lastRunFailed: true, findings: [f("CRITICAL")] })).toMatchObject({ level: "exposed" });
  });
});

// Felipe 2026-10-06: an audit in progress is shown as in progress, and the
// status keeps reading the last finished audit until the new one is done.
describe("auditState", () => {
  const run = (status: string, id: string) => ({ status, id });
  it("keeps the last finished audit while a newer one runs", () => {
    const s = auditState([run("running", "b"), run("complete", "a")]);
    expect(s.current?.id).toBe("b");
    expect(s.finished?.id).toBe("a");
  });
  it("treats a queued audit as in progress and a failed one as finished", () => {
    const s = auditState([run("queued", "c"), run("failed", "b"), run("complete", "a")]);
    expect(s.current?.id).toBe("c");
    expect(s.finished?.id).toBe("b");
  });
  it("has nothing in progress when the newest run is done", () => {
    expect(auditState([run("complete", "a")])).toEqual({ current: null, finished: run("complete", "a") });
    expect(auditState([])).toEqual({ current: null, finished: null });
  });
});
