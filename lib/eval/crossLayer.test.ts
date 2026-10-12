import { beforeEach, describe, expect, it, vi } from "vitest";
import type { RouteFact } from "@/lib/graph/routeInventory";
import type { StackReport } from "@/lib/agent/stack";
import type { RepositoryDatabaseEvidence } from "@/lib/graph/repositoryDatabase";

// The cross-layer chain, end to end with production's own functions (X1,
// Felipe 2026-10-12: "this is not even with traffic and the stack, so have a
// way to truly make sure this works"). Only storage is stubbed: the bound
// database snapshot is projected by projectRepositoryDatabaseEvidence, turned
// into live facts by loadLiveFacts, carried to the verifier by verifyItems,
// admitted by the verification path and judged by isConfirmed and verdictOf.
const loadGraphInput = vi.fn();
vi.mock("@/lib/graph/graphRun", () => ({ loadGraphInput }));
vi.mock("@/lib/deep/providerRepositoryMap", () => ({ loadVerifiedProviderProjects: vi.fn().mockResolvedValue(new Set()) }));
vi.mock("@/lib/supabase", () => ({ getSupabaseAdmin: vi.fn() }));

const { projectRepositoryDatabaseEvidence } = await import("@/lib/graph/repositoryDatabase");
const { loadLiveFacts } = await import("@/lib/agent/liveFacts");
const { reasoningContext } = await import("@/lib/intelligence/reasoning");
const { admitVerified, guardAnswer, verificationTasks } = await import("./agentPath");
const { isConfirmed } = await import("@/lib/agent/confirmed");
const { verdictOf } = await import("@/lib/verdict");

const handler = "app/api/orders/route.ts";
const source = [
  "export async function GET() {",
  "  const supabase = await createClient();",
  "  const { data: { user } } = await supabase.auth.getUser();",
  "  if (!user) return new Response(null, { status: 401 });",
  "  return Response.json(await supabase.from(\"orders\").select(\"*\"));",
  "}",
].join("\n");
const route: RouteFact = { path: "/api/orders", file: handler, methods: ["GET"], tables: ["orders"],
  authenticated: true, machineGated: false, usesServiceRole: false, ownershipFiltered: false, identityReadable: true, identityGap: null,
  dataReadable: true, dataGap: null, ownershipReadable: true, ownershipGap: null, serviceRoleReadable: true, machineGateReadable: true,
  machineGateGap: null, via: [] };
const supabase = { tools: [{ id: "next", name: "Next.js", kind: "framework", evidence: "package.json", usedIn: [] },
  { id: "supabase", name: "Supabase", kind: "database", evidence: "package.json", usedIn: [] }],
  authUnknown: false, databaseUnknown: false } as unknown as StackReport;

const snapshot = (rlsEnabled: boolean, qual: string): RepositoryDatabaseEvidence => ({
  repositoryId: "repo-a", associationMethod: "customer_confirmed", admission: "connection-matched",
  snapshots: { directPostgresSnapshot: {
    collector: "direct-postgres", authzProvider: "postgres-rls", connectionFingerprint: "a".repeat(64),
    recordedAt: "2026-10-12T00:00:00Z", completeness: "unknown",
    policies: [{ schemaname: "public", tablename: "orders", policyname: "p", permissive: "PERMISSIVE", roles: ["authenticated"],
      cmd: "SELECT", qual, with_check: null }],
    scanTables: [{ name: "orders", rlsEnabled }],
  } },
} as unknown as RepositoryDatabaseEvidence);

/** The founder's status after one audit of this repository with the database in the given state. */
async function audit(evidence: RepositoryDatabaseEvidence, verdict: "confirmed" | "refuted") {
  loadGraphInput.mockImplementation(async (_u: string, repo?: string) =>
    repo ? { routes: [route], ...projectRepositoryDatabaseEvidence(evidence) } : {});
  const liveFacts = await loadLiveFacts("u", "repo-a");
  const ctx = reasoningContext({ routes: [route], stack: supabase, tables: ["orders"], files: [handler], liveFacts,
    possessionGates: new Map(), oneIdAccess: new Map(), hasDatabase: true })!;
  const admitted = guardAnswer(ctx, [{ entry: "/api/orders", attackClass: "missing_authorization",
    title: "Any signed-in user can read every order", consequence: "A signed-in caller reads every customer's orders.",
    citedFiles: [handler], citedTables: ["orders"] }]).admitted;
  const [task] = verificationTasks(ctx, admitted, () => source);
  const citations = [{ role: "reach", path: handler, line: 4, quote: "  if (!user) return new Response(null, { status: 401 });" },
    { role: "data", path: handler, line: 5, quote: "  return Response.json(await supabase.from(\"orders\").select(\"*\"));" }];
  const kept = admitVerified(ctx, task, [{ id: "0", verdict, severity: "critical",
    statement: "Any signed-in user can read every customer's orders.", reason: "db fact", citations }], "repo-a");
  const findings = kept.findings.map((f) => ({ ...f, confirmed: isConfirmed(f) }));
  const status = verdictOf({ findings: findings.filter((f) => f.confirmed), blockedPrs: 0, audited: true, lastRunFailed: false,
    toReview: findings.filter((f) => !f.confirmed).length, unread: 0 });
  return { liveFacts, task, findings, status };
}

describe("cross-layer: a bound database reaches the founder's status", () => {
  beforeEach(() => loadGraphInput.mockReset());

  it("an unscoped signed-in query on a table with row security off is a confirmed issue carrying the live fact", async () => {
    const { liveFacts, task, findings, status } = await audit(snapshot(false, "true"), "confirmed");
    expect(liveFacts.map((f) => f.id)).toEqual(["db:public.orders:rls-off"]);
    expect(task.items[0].facts?.map((f) => f.id)).toEqual(["db:public.orders:rls-off"]);
    expect(JSON.stringify(task.brief)).toContain("row level security off on public.orders");
    expect(findings).toHaveLength(1);
    expect(findings[0].confirmed).toBe(true);
    expect(findings[0].claims).toEqual(expect.arrayContaining([expect.objectContaining({ origin: "live", verified: true })]));
    expect(status.level).not.toBe("clear");
  });

  it("the same code over a filtered table shows the verifier the filter, and a refuted claim leaves the status clear", async () => {
    const { liveFacts, task, findings, status } = await audit(snapshot(true, "(auth.uid() = user_id)"), "refuted");
    expect(liveFacts.map((f) => f.id)).toEqual(["db:public.orders:rls-filtered"]);
    expect(task.items[0].facts?.map((f) => f.id)).toEqual(["db:public.orders:rls-filtered"]);
    expect(task.hypotheses[0].citedFacts ?? []).toEqual([]);
    expect(findings).toEqual([]);
    expect(status.level).toBe("clear");
  });

  it("a database not bound to this repository adds nothing", async () => {
    const { liveFacts, task } = await audit({ ...snapshot(false, "true"), admission: "unknown" }, "refuted");
    expect(liveFacts).toEqual([]);
    expect(task.items[0]).not.toHaveProperty("facts");
  });
});
