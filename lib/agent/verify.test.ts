import { describe, expect, it } from "vitest";
import { VERIFY_SCHEMA, VERIFY_SYSTEM, applyVerdicts, buildVerifyPrompt, checkVerdicts, parseVerdicts, resolveImport, selectVerifyContext, type RawVerdict, type VerifyItem } from "./verify";

const files = new Map([
  ["app/api/invoices/[id]/route.ts", 'import { db } from "@/lib/db";\nimport { helper } from "../../helper";\nexport async function GET(req, { params }) {\n  const row = await db.from("invoices").select("*").eq("id", params.id).single();\n  return Response.json(row);\n}'],
  ["lib/db.ts", "export const db = createAdmin();"],
  ["app/api/helper.ts", "export const helper = 1;"],
  ["lib/unrelated.ts", "x"],
]);
const item: VerifyItem = {
  id: "c1", entry: "/api/invoices/[id]", attackClass: "missing_authorization", title: "Anyone reads any invoice",
  consequence: "No session", citedFiles: ["app/api/invoices/[id]/route.ts"], handlerFile: "app/api/invoices/[id]/route.ts",
};
const confirmed = (citations: RawVerdict["citations"]): RawVerdict =>
  ({ id: "c1", verdict: "confirmed", severity: "critical", statement: "Anyone can read any invoice.", reason: "r", citations });
const shown = new Set(files.keys());

describe("verifier context", () => {
  it("resolves relative and alias imports to archive files", () => {
    const names = new Set(files.keys());
    expect(resolveImport("app/api/invoices/[id]/route.ts", "@/lib/db", names)).toBe("lib/db.ts");
    expect(resolveImport("app/api/invoices/[id]/route.ts", "../../helper", names)).toBe("app/api/helper.ts");
    expect(resolveImport("app/api/invoices/[id]/route.ts", "next/server", names)).toBeNull();
  });

  it("shows the handler first, then what it imports, and names what did not fit", () => {
    const all = selectVerifyContext([item], files);
    expect(all.shown).toEqual(["app/api/invoices/[id]/route.ts", "lib/db.ts", "app/api/helper.ts"]);
    const tight = selectVerifyContext([item], files, files.get("app/api/invoices/[id]/route.ts")!.length + 5);
    expect(tight.shown).toEqual(["app/api/invoices/[id]/route.ts"]);
    expect(tight.omitted).toEqual(["lib/db.ts", "app/api/helper.ts"]);
    expect(buildVerifyPrompt([item], files, tight)).toMatch(/not shown \(budget\): lib\/db\.ts, app\/api\/helper\.ts/);
  });
});

describe("deterministic admission of verdicts", () => {
  it("keeps a confirmed verdict whose quotes are on the cited lines", () => {
    const [v] = checkVerdicts([confirmed([
      { role: "reach", path: "app/api/invoices/[id]/route.ts", line: 3, quote: "export async function GET(req, { params }) {" },
      { role: "data", path: "app/api/invoices/[id]/route.ts", line: 4, quote: 'db.from("invoices").select("*").eq("id", params.id)' },
    ])], [item], files, shown);
    expect(v.verdict).toBe("confirmed");
    expect(v.citationProblem).toBeNull();
  });

  it("downgrades a confirmed verdict with an invented quote, a missing role, or an unshown file", () => {
    const invented = checkVerdicts([confirmed([
      { role: "reach", path: "app/api/invoices/[id]/route.ts", line: 3, quote: "export async function GET" },
      { role: "data", path: "app/api/invoices/[id]/route.ts", line: 4, quote: "await supabase.from('users')" },
    ])], [item], files, shown)[0];
    expect(invented).toMatchObject({ verdict: "unverified", citationProblem: expect.stringMatching(/quote not found/) });

    const noData = checkVerdicts([confirmed([{ role: "reach", path: "app/api/invoices/[id]/route.ts", line: 3, quote: "export async function GET" }])],
      [item], files, shown)[0];
    expect(noData).toMatchObject({ verdict: "unverified", citationProblem: "no data citation" });

    const unshown = checkVerdicts([confirmed([
      { role: "reach", path: "app/api/invoices/[id]/route.ts", line: 3, quote: "export async function GET" },
      { role: "data", path: "lib/db.ts", line: 1, quote: "createAdmin()" },
    ])], [item], files, new Set(["app/api/invoices/[id]/route.ts"]))[0];
    expect(unshown.citationProblem).toMatch(/not shown/);
  });

  it("treats a claim the verifier skipped as unverified, and unreadable output as nothing", () => {
    expect(checkVerdicts([], [item], files, shown)[0]).toMatchObject({ verdict: "unverified", citationProblem: "missing" });
    expect(parseVerdicts("not json")).toBeNull();
    expect(parseVerdicts('{"verdicts":[]}')).toEqual([]);
  });

  it("passes refuted and unverified verdicts through without admission", () => {
    const [v] = checkVerdicts([{ ...confirmed([]), verdict: "refuted" }], [item], files, shown);
    expect(v.verdict).toBe("refuted");
  });
});

describe("applying verdicts to admitted proposals", () => {
  const admitted = [
    { entry: "/a", attackClass: "missing_authorization", title: "A", consequence: "old wording", citedFiles: ["a.ts"] },
    { entry: "/b", attackClass: "missing_authorization", title: "B", consequence: "b", citedFiles: ["b.ts"] },
    { entry: "/c", attackClass: "missing_authorization", title: "C", consequence: "c", citedFiles: ["c.ts"] },
  ];
  const verdict = (id: string, v: RawVerdict["verdict"], statement = "") =>
    ({ id, verdict: v, severity: "high" as const, statement, reason: "", citations: [], citationProblem: null });

  it("keeps only confirmed proposals, in the verifier's plain wording, and counts the rest", () => {
    const out = applyVerdicts(admitted, [verdict("0", "confirmed", "Anyone can read every team's invoices."), verdict("1", "refuted"), verdict("2", "unverified")]);
    // Marked, so buildFindings keeps the proven sentence (CORPUS-5 agent path).
    expect(out.kept).toEqual([{ ...admitted[0], consequence: "Anyone can read every team's invoices.", provenStatement: true }]);
    expect(out.refuted).toBe(1);
    expect(out.unverified).toBe(1);
  });

  // Release run r6 (2026-10-12, both labelers: real, partly accurate): the
  // proposer's title said "any student" while the verifier's sentence was
  // exact. The verifier writes the title too; the proposer's stands only
  // when the verifier gave none.
  it("takes the verifier's title with its statement", () => {
    const out = applyVerdicts(admitted, [{ ...verdict("0", "confirmed", "Any signed-in user can enroll an unassigned student."),
      title: "Any signed-in user can enroll unassigned students" }]);
    expect(out.kept[0]).toMatchObject({ title: "Any signed-in user can enroll unassigned students",
      consequence: "Any signed-in user can enroll an unassigned student." });
    expect(applyVerdicts(admitted, [verdict("0", "confirmed", "x.")]).kept[0].title).toBe("A");
  });

  it("never keeps a proposal the verifier did not answer", () => {
    const out = applyVerdicts(admitted, [verdict("0", "confirmed")]);
    expect(out.kept).toEqual([admitted[0]]);
    expect(out.unverified).toBe(2);
  });
});

// A8 batch 6 (2026-10-09): the verifier confirmed a debug route whose Prisma
// query the schema rejects. The schema now goes with every batch; the
// instructions say what to do with it.
describe("VERIFY_SYSTEM and the schema", () => {
  it("tells the verifier to refute a query the listed schema cannot run", () => {
    expect(VERIFY_SYSTEM).toMatch(/schema file is listed/);
    expect(VERIFY_SYSTEM).toMatch(/does not run/);
  });
});

// Release run r2 (2026-10-12, both labelers: accurate, not real): a route
// overwrote any user's stored API key that nothing reads, and another set a
// "role" that is only a display label. Reach and no control held; the data
// did not matter. The verifier must check that the value is used.
describe("VERIFY_SYSTEM and data that does not matter", () => {
  it("tells the verifier to refute a write to a value nothing uses for access or secrets", () => {
    expect(VERIFY_SYSTEM).toMatch(/nothing reads/);
    expect(VERIFY_SYSTEM).toMatch(/only displayed/);
  });
});

// Release run r3 (2026-10-12, both labelers: real, statement partly
// accurate): "or resetting their own" when the code only increments, and
// "any other buyer's order" when that needs a random order id. The
// founder's sentence says only what the quoted lines prove.
describe("VERIFY_SYSTEM and the founder's sentence", () => {
  it("asks for a statement that claims no more than the code shows", () => {
    expect(VERIFY_SYSTEM).toMatch(/no effect the quoted lines do not show/);
    expect(VERIFY_SYSTEM).toMatch(/who knows its id/);
  });
});

describe("VERIFY_SYSTEM and the title", () => {
  it("asks the verifier for a title no broader than its statement", () => {
    expect(VERIFY_SYSTEM).toMatch(/title/);
    expect(VERIFY_SCHEMA.properties.verdicts.items.required).toContain("title");
  });
});

// Release attempt 3 (2026-10-13, both labelers): "every order" where the route
// returns counts and five titles, "all users" past a role filter, "fields
// they choose" where three are writable (V5); and fields a public list
// already returns, reported as a leak (V4).
describe("VERIFY_SYSTEM and data scope", () => {
  it("names only what the response returns, with its filters", () => {
    expect(VERIFY_SYSTEM).toMatch(/name only the fields/i);
    expect(VERIFY_SYSTEM).toMatch(/filter/i);
  });
  it("refutes data another public route already serves", () => {
    expect(VERIFY_SYSTEM).toMatch(/already returns the same fields/i);
  });
});

// Release attempt 4 (2026-10-14, both labelers partly accurate): the
// statement said "ShipLock's host" sends the attacker's email; it is the
// customer's own app. The founder's sentence names the app, never ShipLock.
describe("VERIFY_SYSTEM and who acts", () => {
  it("names the app as the actor, never ShipLock", () => {
    expect(VERIFY_SYSTEM).toMatch(/the app, never ShipLock/i);
  });
});
