import { describe, expect, it } from "vitest";
import { applyVerdicts, buildVerifyPrompt, checkVerdicts, parseVerdicts, resolveImport, selectVerifyContext, type RawVerdict, type VerifyItem } from "./verify";

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

  it("never keeps a proposal the verifier did not answer", () => {
    const out = applyVerdicts(admitted, [verdict("0", "confirmed")]);
    expect(out.kept).toEqual([admitted[0]]);
    expect(out.unverified).toBe(2);
  });
});
