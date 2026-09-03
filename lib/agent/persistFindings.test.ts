import { describe, expect, it } from "vitest";
import { persistFindings } from "./audit";
import type { AgentFinding } from "./findings";

/**
 * THE CONVERGENCE PROPERTY, PROVEN RATHER THAN ARGUED.
 *
 * persistFindings used to archive first and insert second, as two statements
 * with no transaction and both errors discarded. A death between them archived
 * the previous findings and wrote nothing in their place, so the dashboard read
 * ZERO and rendered clean — "absent is not clean" violated in the one place it
 * matters most.
 *
 * Option C inverts the order and makes the insert idempotent (migration 051).
 * The guarantee is NOT that the window is gone — it is that the window now
 * fails in the safe direction: too much, never too little. These tests crash it
 * in BOTH positions and assert the store never goes empty, then assert that a
 * subsequent clean run converges.
 */

/** A minimal stand-in for the rows deep_findings would hold. */
interface Row { repository_id: string; finding_id: string; archived_at: string | null }

/**
 * A fake PostgREST client over an in-memory table.
 *
 * `crashOn` makes the named statement throw, which is how a mid-write death is
 * reproduced deterministically. Everything else behaves like the real builder
 * closely enough for the ordering property under test.
 */
function fakeDb(rows: Row[], crashOn: "insert" | "archive" | null = null) {
  return {
    rows,
    from() {
      return {
        upsert(records: Row[], _opts: unknown) {
          if (crashOn === "insert") throw new Error("process died mid-insert");
          for (const r of records) {
            const live = rows.find(
              (x) => x.repository_id === r.repository_id && x.finding_id === r.finding_id && x.archived_at === null,
            );
            if (!live) rows.push({ ...r, archived_at: null });   // the partial unique index
          }
          return { error: null };
        },
        update(patch: { archived_at: string }) {
          const b = {
            _repo: "", _notIn: [] as string[],
            eq(_c: string, v: string) { b._repo = v; return b; },
            is(_c: string, _v: null) { return b; },
            not(_c: string, _op: string, list: string) {
              b._notIn = list.slice(1, -1).split(",").map((s) => s.replace(/^"|"$/g, ""));
              return b;
            },
            then(res: (v: { error: null }) => unknown) {
              if (crashOn === "archive") throw new Error("process died mid-archive");
              for (const r of rows) {
                if (r.repository_id === b._repo && r.archived_at === null && !b._notIn.includes(r.finding_id)) {
                  r.archived_at = patch.archived_at;
                }
              }
              return res({ error: null });
            },
          };
          return b;
        },
      };
    },
  };
}

const finding = (id: string): AgentFinding => ({
  id, title: id, consequence: "c", severity: "CRITICAL", confidence: "inferred",
  attackClass: "missing_authorization", entry: "/api/x", file: "app/api/x/route.ts",
  blastRadius: null, fixKind: "pr", claims: [],
});

const open = (rows: Row[]) => rows.filter((r) => r.archived_at === null).map((r) => r.finding_id).sort();

describe("persistFindings converges and never empties", () => {
  it("writes the new set and retires what did not reproduce", async () => {
    const rows: Row[] = [
      { repository_id: "r1", finding_id: "old-gone", archived_at: null },
      { repository_id: "r1", finding_id: "still-here", archived_at: null },
    ];
    const db = fakeDb(rows);
    await persistFindings("u", "r1", "run2", [finding("still-here"), finding("brand-new")], db as never);
    expect(open(rows)).toEqual(["brand-new", "still-here"]);
  });

  it("CRASH BEFORE THE INSERT leaves the previous findings intact, never zero", async () => {
    const rows: Row[] = [{ repository_id: "r1", finding_id: "old", archived_at: null }];
    const db = fakeDb(rows, "insert");
    await expect(
      persistFindings("u", "r1", "run2", [finding("new")], db as never),
    ).rejects.toThrow(/mid-insert/);
    expect(open(rows)).toEqual(["old"]);          // NOT []
  });

  it("CRASH AFTER THE INSERT leaves both old and new visible, never zero", async () => {
    const rows: Row[] = [{ repository_id: "r1", finding_id: "old", archived_at: null }];
    const db = fakeDb(rows, "archive");
    await expect(
      persistFindings("u", "r1", "run2", [finding("new")], db as never),
    ).rejects.toThrow(/mid-archive/);
    expect(open(rows)).toEqual(["new", "old"]);   // too much, never too little
  });

  it("a later successful run converges from the crashed state", async () => {
    const rows: Row[] = [{ repository_id: "r1", finding_id: "old", archived_at: null }];
    try { await persistFindings("u", "r1", "run2", [finding("new")], fakeDb(rows, "archive") as never); } catch { /* the crash */ }
    expect(open(rows)).toEqual(["new", "old"]);            // duplicated state
    await persistFindings("u", "r1", "run3", [finding("new")], fakeDb(rows) as never);
    expect(open(rows)).toEqual(["new"]);                   // converged
  });

  it("re-running the same findings is idempotent — no duplicate rows", async () => {
    const rows: Row[] = [];
    await persistFindings("u", "r1", "run1", [finding("a"), finding("b")], fakeDb(rows) as never);
    await persistFindings("u", "r1", "run2", [finding("a"), finding("b")], fakeDb(rows) as never);
    expect(rows.filter((r) => r.archived_at === null)).toHaveLength(2);
  });

  it("an empty result archives everything rather than writing nothing", async () => {
    // A genuinely clean audit must still retire what it fixed.
    const rows: Row[] = [{ repository_id: "r1", finding_id: "fixed", archived_at: null }];
    await persistFindings("u", "r1", "run2", [], fakeDb(rows) as never);
    expect(open(rows)).toEqual([]);
  });

  it("never touches another repository's findings", async () => {
    const rows: Row[] = [
      { repository_id: "r1", finding_id: "mine", archived_at: null },
      { repository_id: "r2", finding_id: "theirs", archived_at: null },
    ];
    await persistFindings("u", "r1", "run2", [], fakeDb(rows) as never);
    expect(rows.find((r) => r.repository_id === "r2")!.archived_at).toBeNull();
  });
});
