import { beforeEach, describe, expect, it, vi } from "vitest";
import { assessReachability, triageByReachability } from "./reachability";

const reads = vi.hoisted(() => ({ user_profiles: vi.fn(), repositories: vi.fn(), graph_facts: vi.fn() }));
const filters = vi.hoisted(() => vi.fn());
vi.mock("@/lib/supabase", () => ({
  getSupabaseAdmin: () => ({ from: (table: keyof typeof reads) => {
    const query = {
      eq: (key: string, value: unknown) => { filters(table, key, value); return query; },
      maybeSingle: () => reads[table](),
      then: (resolve: (value: unknown) => unknown, reject: (error: unknown) => unknown) => reads[table]().then(resolve, reject),
    };
    return { select: () => query };
  } }),
}));

import { loadRepositoryReachability, loadRepositoryDependencies } from "./repositorySource";
import { loadReachabilityIndex, loadGraphInput, canRetireGraphFindings } from "./graphRun";
import { findAttackPaths } from "./attackPaths";
const snapshot = {
  repositoryFullName: "acme/one", installationId: "42", ref: "main",
  recordedAt: "2026-09-16T10:00:00Z", completeness: "partial",
  filesAttempted: 2, filesRead: 2, hasEntryPoints: true,
  liveFiles: ["app/page.tsx", "lib/shared.ts"], routes: [], dependencies: [],
};
const now = Date.parse("2026-09-16T11:00:00Z");
const finding = (repo: string, path = "lib/shared.ts") => `${repo}::github:credential:example:${path}`;
const route = {
  path: "/api/invoices", file: "app/api/invoices/route.ts", methods: ["GET"], tables: ["invoices"],
  authenticated: false, machineGated: false, usesServiceRole: false, ownershipFiltered: false,
  identityReadable: true, ownershipReadable: true, dataReadable: true, machineGateReadable: true, serviceRoleReadable: true,
  identityGap: null, ownershipGap: null, dataGap: null, machineGateGap: null, via: [],
};
async function scoped(repositoryId: string) {
  const clock = vi.spyOn(Date, "now").mockReturnValue(now);
  try { return await loadGraphInput("u", repositoryId); }
  finally { clock.mockRestore(); }
}

beforeEach(() => {
  filters.mockReset();
  reads.user_profiles.mockReset().mockResolvedValue({ data: {
    github_installation_id: 42, github_connected_at: "2026-09-16T09:00:00Z",
  }, error: null });
  reads.repositories.mockReset().mockResolvedValue({ data: [
    { id: "repo-one", full_name: "Acme/One", default_branch: "main" },
    { id: "repo-two", full_name: "acme/two", default_branch: "main" },
  ], error: null });
  reads.graph_facts.mockReset().mockResolvedValue({ data: { facts: { repositories: [snapshot] } }, error: null });
});

describe("Step 2: repository-scoped dependency admission", () => {
  it("keeps differing versions of the same dependency in their own repositories", async () => {
    const clock = vi.spyOn(Date, "now").mockReturnValue(now);
    try {
      reads.graph_facts.mockResolvedValue({ data: { facts: { dependencies: [{ name: "legacy", version: "0" }], repositories: [
        { ...snapshot, dependencies: [{ name: "hono", version: "1" }] },
        { ...snapshot, repositoryFullName: "acme/two", dependencies: [{ name: "hono", version: "2" }] },
      ] } } });
      const result = await loadRepositoryDependencies("u");
      expect(result.map((item) => [item.repositoryId, item.dependencies[0].version])).toEqual([["repo-one", "1"], ["repo-two", "2"]]);
    } finally { clock.mockRestore(); }
  });
  it.each([undefined, null, [{ name: "hono", version: 1 }], [{ name: "hono", version: "1" }, { name: "hono", version: "2" }]])(
    "refuses unread or ambiguous dependency payloads", async (dependencies) => {
      const clock = vi.spyOn(Date, "now").mockReturnValue(now);
      try {
        reads.graph_facts.mockResolvedValue({ data: { facts: { repositories: [{ ...snapshot, dependencies }] } } });
        expect(await loadRepositoryDependencies("u")).toEqual([]);
      } finally { clock.mockRestore(); }
    });
});

describe("Step 2C-3-B: repository-scoped graph source", () => {
  it("admits only the requested repository's validated routes, without unbound provider facts", async () => {
    reads.graph_facts.mockResolvedValue({ data: { facts: {
      routes: [{ ...route, path: "/aggregate-must-not-leak" }],
      policies: [], scanTables: [{ name: "invoices", rlsEnabled: false }], hotPaths: [{ path: "/api/invoices", suspiciousRequests: 99 }],
      repositories: [{ ...snapshot, routes: [route] }, { ...snapshot, repositoryFullName: "acme/two", routes: [{ ...route, authenticated: true }] }],
    } }, error: null });
    const one = await scoped("repo-one");
    const two = await scoped("repo-two");
    expect(one).toEqual({ repositoryId: "repo-one", sourceCoverage: "partial", correlationScope: "source-only", routes: [route],
      databaseEvidence: { repositoryId: "repo-one", associationMethod: "customer_confirmed", admission: "unknown", snapshots: {} } });
    expect(two.routes?.[0].authenticated).toBe(true);
    expect(findAttackPaths(one)).toEqual([]);
    expect(canRetireGraphFindings(one)).toBe(false);
  });

  it("keeps an unknown repository unknown rather than using aggregate routes", async () => {
    expect(await scoped("other-user-repository")).toEqual({ repositoryId: "other-user-repository", sourceCoverage: "unknown", correlationScope: "source-only" });
  });

  it.each([
    { authenticated: "false" }, { identityReadable: undefined }, { file: "/etc/passwd" },
    { methods: ["INVENTED"] }, { tables: null }, { via: [42] },
  ])("rejects malformed route facts without turning them into an empty observation: %j", async (override) => {
    reads.graph_facts.mockResolvedValue({ data: { facts: { repositories: [{ ...snapshot, routes: [{ ...route, ...override }] }] } }, error: null });
    expect(await scoped("repo-one")).toEqual({ repositoryId: "repo-one", sourceCoverage: "unknown", correlationScope: "source-only" });
    // Malformed routes do not revoke independently validated file evidence.
    expect(assessReachability(finding("acme/one"), await loadRepositoryReachability("u", now)).scoreDelta).toBe(20);
  });

  it("refuses colliding route identities instead of letting a Map pick a winner", async () => {
    reads.graph_facts.mockResolvedValue({ data: { facts: { repositories: [{ ...snapshot, routes: [route, { ...route, file: "apps/other/app/api/invoices/route.ts" }] }] } }, error: null });
    expect((await scoped("repo-one")).routes).toBeUndefined();
  });

  it("keeps explicit empty routes partial, never sufficient for retirement", async () => {
    const input = await scoped("repo-one");
    expect(input.routes).toEqual([]);
    expect(canRetireGraphFindings({ ...input, scanTables: [], policies: [] })).toBe(false);
  });

  it("refuses ambiguous selected repository IDs even when full names differ", async () => {
    reads.repositories.mockResolvedValue({ data: [
      { id: "repo-one", full_name: "acme/one", default_branch: "main" },
      { id: "repo-one", full_name: "acme/two", default_branch: "main" },
    ], error: null });
    expect((await scoped("repo-one")).sourceCoverage).toBe("unknown");
  });
});

describe("Step 2C-3-A: selected-repository source admission", () => {
  it("wires the production prioritization loader to repository-only evidence", async () => {
    const clock = vi.spyOn(Date, "now").mockReturnValue(now);
    try {
      const index = await loadReachabilityIndex("u");
      expect(assessReachability(finding("ACME/ONE"), index).scoreDelta).toBe(20);
      expect(assessReachability(finding("acme/two"), index).state).toBe("unknown");
      expect(assessReachability("github:credential:example:lib/shared.ts", index).state).toBe("unknown");
    } finally { clock.mockRestore(); }
  });
  it("admits only the selected repository's own observation and scopes every database read", async () => {
    const index = await loadRepositoryReachability("u", now);
    expect(assessReachability(finding("acme/one"), index).state).toBe("reachable");
    expect(assessReachability(finding("acme/two"), index).state).toBe("unknown");
    expect(filters.mock.calls).toEqual([
      ["user_profiles", "id", "u"], ["repositories", "user_id", "u"],
      ["repositories", "selected", true], ["graph_facts", "user_id", "u"], ["graph_facts", "collector", "source"],
    ]);
  });

  it("does not let identical paths in another repository promote a finding", async () => {
    reads.graph_facts.mockResolvedValue({ data: { facts: { repositories: [snapshot, {
      ...snapshot, repositoryFullName: "acme/two", liveFiles: ["app/page.tsx"],
    }] } }, error: null });
    const index = await loadRepositoryReachability("u", now);
    expect(assessReachability(finding("acme/one"), index).scoreDelta).toBe(20);
    expect(assessReachability(finding("acme/two"), index).scoreDelta).toBe(0);
  });

  it("never demotes an unobserved file from a partial snapshot, including tooling paths", async () => {
    const index = await loadRepositoryReachability("u", now);
    for (const path of ["lib/unobserved.ts", "scripts/seed.ts"]) {
      expect(assessReachability(finding("acme/one", path), index)).toMatchObject({ state: "unknown", scoreDelta: 0 });
    }
  });

  it("does not guess repository bindings for account-scoped database findings", async () => {
    expect(assessReachability("policy:public.invoices:p:unrestricted_read", await loadRepositoryReachability("u", now)).state).toBe("unknown");
  });

  it("refuses legacy aggregate fallback and preserves all findings", async () => {
    reads.graph_facts.mockResolvedValue({ data: { facts: { liveFiles: ["lib/shared.ts"], hasEntryPoints: true, routes: [] } }, error: null });
    const index = await loadRepositoryReachability("u", now);
    const input = ["acme/one", "acme/two"].map((repo) => ({ id: finding(repo), title: repo, severity: "CRITICAL" }));
    const result = triageByReachability(input, index);
    expect(result).toHaveLength(2);
    expect(result.every((item) => item.reachability.state === "unknown")).toBe(true);
  });

  it.each([
    { repositoryFullName: "acme/unselected" }, { installationId: "99" }, { ref: "old-branch" },
    { recordedAt: "2026-09-16T08:00:00Z" }, { recordedAt: "2099-01-01T00:00:00Z" }, { recordedAt: "invalid" },
    { filesRead: 0 }, { filesRead: 3 }, { filesRead: "2" }, { liveFiles: [42] },
    { completeness: "complete" }, { hasEntryPoints: "true" },
  ])("rejects mismatched/malformed snapshot %j", async (override) => {
    reads.graph_facts.mockResolvedValue({ data: { facts: { repositories: [{ ...snapshot, ...override }] } }, error: null });
    expect(assessReachability(finding("acme/one"), await loadRepositoryReachability("u", now)).state).toBe("unknown");
  });

  it.each([
    { github_installation_id: null, github_connected_at: "2026-09-16T09:00:00Z" },
    { github_installation_id: 42, github_connected_at: null },
    { github_installation_id: 42, github_connected_at: "2026-09-16T10:30:00Z" },
  ])("rejects disconnected/unknown/reconnected authorization %j", async (profile) => {
    reads.user_profiles.mockResolvedValue({ data: profile, error: null });
    expect(assessReachability(finding("acme/one"), await loadRepositoryReachability("u", now)).state).toBe("unknown");
  });

  it("rejects duplicate snapshot identities instead of picking the last writer", async () => {
    reads.graph_facts.mockResolvedValue({ data: { facts: { repositories: [snapshot, { ...snapshot, repositoryFullName: "Acme/One" }] } }, error: null });
    expect(assessReachability(finding("acme/one"), await loadRepositoryReachability("u", now)).state).toBe("unknown");
  });

  it("rejects ambiguous selected identities", async () => {
    reads.repositories.mockResolvedValue({ data: [
      { id: "one", full_name: "acme/one", default_branch: "main" },
      { id: "two", full_name: "Acme/One", default_branch: "main" },
    ], error: null });
    expect(assessReachability(finding("acme/one"), await loadRepositoryReachability("u", now)).state).toBe("unknown");
  });

  it("rejects a valid snapshot when a malformed duplicate carries the same identity", async () => {
    reads.graph_facts.mockResolvedValue({ data: { facts: { repositories: [snapshot, {
      repositoryFullName: "Acme/One", filesRead: "invalid",
    }] } }, error: null });
    expect(assessReachability(finding("acme/one"), await loadRepositoryReachability("u", now)).state).toBe("unknown");
  });

  it.each([null, {}, Array.from({ length: 11 }, () => snapshot)])("rejects missing, malformed or over-cap snapshot collections %j", async (repositories) => {
    reads.graph_facts.mockResolvedValue({ data: { facts: { repositories } }, error: null });
    expect(assessReachability(finding("acme/one"), await loadRepositoryReachability("u", now)).state).toBe("unknown");
  });

  it("rejects malformed selected-repository rows", async () => {
    reads.repositories.mockResolvedValue({ data: [{ id: "one", full_name: "acme/one" }], error: null });
    expect(assessReachability(finding("acme/one"), await loadRepositoryReachability("u", now)).state).toBe("unknown");
  });

  it.each(["user_profiles", "repositories", "graph_facts"] as const)("fails closed on %s read errors without logging stored values", async (table) => {
    reads[table].mockResolvedValue({ data: null, error: { message: "private-value-do-not-log" } });
    const log = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      expect(assessReachability(finding("acme/one"), await loadRepositoryReachability("u", now)).state).toBe("unknown");
      expect(JSON.stringify(log.mock.calls)).not.toContain("private-value-do-not-log");
    } finally { log.mockRestore(); }
  });
});
