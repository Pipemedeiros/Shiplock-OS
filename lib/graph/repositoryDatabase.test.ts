import { beforeEach, expect, it, vi } from "vitest";
import { loadRepositoryDatabaseEvidence, projectRepositoryDatabaseEvidence } from "./repositoryDatabase";
import { findAttackPaths } from "./attackPaths";
import type { RouteFact } from "./routeInventory";

const mocks = vi.hoisted(() => ({ read: vi.fn(), current: vi.fn(), direct: vi.fn(), supabase: vi.fn(), filters: vi.fn() }));
vi.mock("@/lib/supabase", () => ({ getSupabaseAdmin: () => ({ from: () => {
  const query = { select: () => query, eq: (key: string, value: string) => { mocks.filters(key, value); return query; }, maybeSingle: mocks.read };
  return query;
} }) }));
vi.mock("./databaseSource", () => ({ loadCurrentDatabaseEvidence: mocks.current }));
vi.mock("@/lib/deep/databaseRepositoryBinding", () => ({ getDirectRepositoryBindings: mocks.direct }));
vi.mock("@/lib/deep/supabaseRepositoryBinding", () => ({ getSupabaseRepositoryBindings: mocks.supabase }));
const snapshots = {
  directPostgresSnapshot: { connectionFingerprint: "direct", columns: [{ table: "t", column: "owner_id", type: "uuid" }] },
  supabaseManagementSnapshot: { connectionFingerprint: "management", projectRef: "a", columns: [{ table: "t", column: "owner_id", type: "uuid" }] },
  supabaseEndpointSnapshot: { connectionFingerprint: "endpoint", projectRef: "b", endpointUrl: "https://b.supabase.co", rlsReadability: "unknown", tableReports: [] },
};
const confirmation = { available: true, bindings: [{ repositoryId: "repo-a" }] };
beforeEach(() => {
  vi.clearAllMocks();
  mocks.read.mockResolvedValue({ data: { facts: snapshots }, error: null });
  mocks.current.mockResolvedValue({ admission: "connection-matched", snapshots });
  mocks.direct.mockResolvedValue({ ...confirmation, connectionFingerprint: "direct" });
  mocks.supabase.mockImplementation(async (_user, collector) => collector === "supabase-management"
    ? { ...confirmation, connectionFingerprint: "management", projectRef: "a", endpointUrl: null }
    : { ...confirmation, connectionFingerprint: "endpoint", projectRef: "b", endpointUrl: "https://b.supabase.co" });
});
it("admits only the explicitly confirmed repository and keeps transports separate", async () => {
  expect(await loadRepositoryDatabaseEvidence("owner", "repo-a")).toEqual({ repositoryId: "repo-a",
    associationMethod: "customer_confirmed", admission: "connection-matched", snapshots });
  expect(mocks.filters).toHaveBeenCalledWith("user_id", "owner");
  expect((await loadRepositoryDatabaseEvidence("owner", "repo-b")).snapshots).toEqual({});
});
it("excludes a credential changed between snapshot and confirmation reads", async () => {
  mocks.direct.mockResolvedValue({ ...confirmation, connectionFingerprint: "replacement" });
  expect((await loadRepositoryDatabaseEvidence("owner", "repo-a")).snapshots.directPostgresSnapshot).toBeUndefined();
});
it.each(["project", "endpoint", "credential", "binding", "unavailable"])("rejects inconsistent Supabase %s context", async (kind) => {
  mocks.supabase.mockResolvedValue({ ...confirmation, connectionFingerprint: kind === "credential" ? "other" : "endpoint",
    projectRef: kind === "project" ? "other" : "b", endpointUrl: kind === "endpoint" ? "https://other.supabase.co" : "https://b.supabase.co",
    ...(kind === "binding" ? { bindings: [] } : {}), ...(kind === "unavailable" ? { available: false } : {}) });
  const result = await loadRepositoryDatabaseEvidence("owner", "repo-a");
  expect(result.snapshots.supabaseManagementSnapshot).toBeUndefined();
  expect(result.snapshots.supabaseEndpointSnapshot).toBeUndefined();
});
it("isolates binding read errors without admitting the failed transport", async () => {
  mocks.direct.mockRejectedValue(new Error("storage"));
  const result = await loadRepositoryDatabaseEvidence("owner", "repo-a");
  expect(result.snapshots.directPostgresSnapshot).toBeUndefined();
  expect(result.snapshots.supabaseManagementSnapshot).toEqual(snapshots.supabaseManagementSnapshot);
});
it("fails unknown on a snapshot read error before reading bindings", async () => {
  mocks.read.mockResolvedValue({ data: null, error: { message: "storage" } });
  expect((await loadRepositoryDatabaseEvidence("owner", "repo-a")).admission).toBe("unknown");
  expect(mocks.direct).not.toHaveBeenCalled(); expect(mocks.supabase).not.toHaveBeenCalled();
});

const route: RouteFact = { path: "/api/invoices", file: "app/api/invoices/route.ts", methods: ["GET"], tables: ["invoices"],
  authenticated: false, machineGated: false, usesServiceRole: false, ownershipFiltered: false,
  identityReadable: true, ownershipReadable: true, dataReadable: true, machineGateReadable: true, serviceRoleReadable: true,
  identityGap: null, ownershipGap: null, dataGap: null, machineGateGap: null, via: [] };
const directSnapshot = { collector: "postgres-direct" as const, authzProvider: "postgres-rls" as const,
  connectionFingerprint: "a".repeat(64), recordedAt: "2026-09-01T00:00:00Z", completeness: "unknown" as const,
  policies: [], scanTables: [{ name: "invoices", rlsEnabled: false }] };
const managementSnapshot = { collector: "supabase-management" as const, authzProvider: "postgres-rls" as const,
  connectionFingerprint: "b".repeat(64), projectRef: "project", recordedAt: "2026-09-01T00:00:00Z",
  completeness: "unknown" as const, policies: [], advisors: [], authConfig: null };

it("projects one confirmed direct database into repository-bound attack paths", () => {
  const evidence = { repositoryId: "repo-a", associationMethod: "customer_confirmed" as const,
    admission: "connection-matched" as const, snapshots: { directPostgresSnapshot: directSnapshot } };
  const projected = projectRepositoryDatabaseEvidence(evidence);
  expect(projected).toMatchObject({ correlationScope: "repository-bound", scanTables: directSnapshot.scanTables, policies: [] });
  expect(findAttackPaths({ repositoryId: "repo-a", sourceCoverage: "partial", routes: [route],
    databaseEvidence: evidence, ...projected })).toHaveLength(1);
});

it("projects one confirmed management snapshot without inventing endpoint RLS state", () => {
  const evidence = { repositoryId: "repo-a", associationMethod: "customer_confirmed" as const,
    admission: "connection-matched" as const, snapshots: { supabaseManagementSnapshot: managementSnapshot,
      supabaseEndpointSnapshot: { ...snapshots.supabaseEndpointSnapshot } as never } };
  expect(projectRepositoryDatabaseEvidence(evidence)).toEqual({ correlationScope: "repository-bound",
    authzProvider: "postgres-rls", policies: [], advisors: [], authConfig: null });
});

it("refuses to choose or merge two confirmed control-capable transports", () => {
  const evidence = { repositoryId: "repo-a", associationMethod: "customer_confirmed" as const,
    admission: "connection-matched" as const, snapshots: { directPostgresSnapshot: directSnapshot,
      supabaseManagementSnapshot: managementSnapshot } };
  expect(projectRepositoryDatabaseEvidence(evidence)).toEqual({});
  expect(findAttackPaths({ routes: [route], correlationScope: "source-only", databaseEvidence: evidence })).toEqual([]);
});

it("never promotes endpoint-only reports into database controls", () => {
  expect(projectRepositoryDatabaseEvidence({ repositoryId: "repo-a", associationMethod: "customer_confirmed",
    admission: "connection-matched", snapshots: { supabaseEndpointSnapshot: snapshots.supabaseEndpointSnapshot as never } })).toEqual({});
});
