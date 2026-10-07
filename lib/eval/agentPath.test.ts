import { describe, expect, it } from "vitest";
import type { RouteFact } from "@/lib/graph/routeInventory";
import type { StackReport } from "@/lib/agent/stack";
import { reasoningContext, taskBrief, type ReasoningTask } from "@/lib/intelligence/reasoning";
import { admitVerified, guardAnswer, reasoningBrief, verificationTasks } from "./agentPath";

// Plan item H, option B (Felipe 2026-10-06): measure the whole harness,
// including the customer agent's findings, offline. These helpers must be
// production's own path (lib/intelligence/reasoning.ts) with files in place
// of Supabase and GitHub; only the transport differs.
const handler = "app/api/orders/route.ts";
const source = "export async function GET() {\n  return Response.json(await db.from(\"orders\").select(\"*\"));\n}\n";
const route = (over: Partial<RouteFact> = {}): RouteFact => ({ path: "/api/orders", file: handler, methods: ["GET"], tables: ["orders"],
  authenticated: false, machineGated: false, usesServiceRole: false, ownershipFiltered: false, identityReadable: true, identityGap: null,
  dataReadable: true, dataGap: null, ownershipReadable: true, ownershipGap: null, serviceRoleReadable: true, machineGateReadable: true,
  machineGateGap: null, via: ["lib/db.ts"], ...over });
const next = { tools: [{ id: "next", name: "Next.js", kind: "framework", evidence: "package.json", usedIn: [] }],
  authUnknown: false, databaseUnknown: false } as unknown as StackReport;
const ctx = reasoningContext({ routes: [route()], stack: next, tables: ["orders"], files: [handler, "lib/db.ts"], liveFacts: [],
  possessionGates: new Map(), oneIdAccess: new Map(), hasDatabase: false })!;
const hypothesis = { entry: "/api/orders", attackClass: "missing_authentication", title: "Anyone can read every order",
  consequence: "An anonymous caller reads all orders.", citedFiles: [handler], citedTables: ["orders"] };
const task = (kind: string, context: unknown) => ({ kind, context } as unknown as ReasoningTask);

describe("the agent path, offline", () => {
  it("gives the agent production's exact reasoning brief", () => {
    expect(reasoningBrief(ctx)).toEqual(taskBrief(task("attack_reasoning", ctx)));
  });

  it("judges the answer with production's guard", () => {
    const guard = guardAnswer(ctx, [hypothesis, { ...hypothesis, entry: "/api/nowhere" }]);
    expect(guard.admitted).toHaveLength(1);
    expect(guard.rejected.length).toBeGreaterThan(0);
  });

  it("asks for proof in production's batches and brief, over the files it can read", () => {
    const admitted = guardAnswer(ctx, [hypothesis]).admitted;
    const [v] = verificationTasks(ctx, admitted, (p) => (p === handler ? source : null));
    expect(v.sources).toEqual([{ path: handler, content: source }]);
    expect(v.brief).toEqual(taskBrief(task("attack_verification", { version: 1, hypotheses: v.hypotheses, items: v.items })));
    expect(verificationTasks(ctx, admitted, () => null)).toEqual([]);
  });

  it("admits only a claim whose quotes are on their lines, as a finding with production's caps", () => {
    const admitted = guardAnswer(ctx, [hypothesis]).admitted;
    const [v] = verificationTasks(ctx, admitted, () => source);
    const citations = [{ role: "reach", path: handler, line: 1, quote: "export async function GET() {" },
      { role: "data", path: handler, line: 2, quote: "db.from(\"orders\").select(\"*\")" }];
    const confirmed = { id: "0", verdict: "confirmed", severity: "critical", statement: "Anyone can read every order with one request.", reason: "no check", citations };
    const kept = admitVerified(ctx, v, [confirmed], "repo");
    expect(kept.confirmed).toBe(1);
    expect(kept.findings).toHaveLength(1);
    expect(kept.findings[0]).toMatchObject({ entry: "/api/orders", attackClass: "missing_authentication", severity: "WARNING" });

    const misquoted = admitVerified(ctx, v, [{ ...confirmed, citations: [citations[0], { ...citations[1], quote: "db.from(\"users\")" }] }], "repo");
    expect(misquoted).toMatchObject({ confirmed: 0, unverified: 1 });
    expect(misquoted.findings).toEqual([]);
    expect(admitVerified(ctx, v, [{ ...confirmed, verdict: "refuted" }], "repo")).toMatchObject({ confirmed: 0, refuted: 1, findings: [] });
  });
});
