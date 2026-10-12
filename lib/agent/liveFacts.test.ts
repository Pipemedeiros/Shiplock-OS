import { describe, expect, it, vi, beforeEach } from "vitest";

const loadGraphInput = vi.fn();
const loadVerifiedProviderProjects = vi.fn();
vi.mock("@/lib/graph/graphRun", () => ({ loadGraphInput }));
vi.mock("@/lib/deep/providerRepositoryMap", () => ({ loadVerifiedProviderProjects }));

const { loadLiveFacts } = await import("./liveFacts");

describe("loadLiveFacts", () => {
  beforeEach(() => {
    loadGraphInput.mockReset();
    loadVerifiedProviderProjects.mockReset().mockResolvedValue(new Set(["vercel:p:connection-1"]));
  });

  it("returns nothing when no runtime collector has ever run", async () => {
    // Absent is not empty. An account with nothing connected must not look like
    // one whose providers were read and reported clean, which is the rulesRead
    // mistake on a new surface.
    loadGraphInput.mockResolvedValue({ routes: [] });
    expect(await loadLiveFacts("u", "repo-a")).toEqual([]);
  });

  it("returns nothing, without throwing, when a provider was read and had nothing", async () => {
    loadGraphInput.mockResolvedValue({ runtimeProvidersRead: ["vercel"], runtimeEnvVars: [] });
    expect(await loadLiveFacts("u", "repo-a")).toEqual([]);
  });

  it("makes a credential-shaped variable citable, with a stable id", async () => {
    loadGraphInput.mockResolvedValue({
      runtimeProvidersRead: ["vercel"],
      runtimeEnvVars: [{ key: "STRIPE_SECRET_KEY", target: ["production"], provider: "vercel", projectId: "p", repositoryId: "repo-a", connectionFingerprint: "connection-1" }],
    });
    const facts = await loadLiveFacts("u", "repo-a");
    expect(facts).toHaveLength(1);
    expect(facts[0].id).toBe("vercel:project:p:env:STRIPE_SECRET_KEY");
    expect(facts[0].statement).toContain("production");
  });

  it("ranks a public-prefixed credential first, because it can carry a finding", async () => {
    loadGraphInput.mockResolvedValue({
      runtimeProvidersRead: ["vercel"],
      runtimeEnvVars: [
        { key: "DATABASE_PASSWORD", target: ["production"], provider: "vercel", projectId: "p", repositoryId: "repo-a", connectionFingerprint: "connection-1" },
        { key: "NEXT_PUBLIC_SERVICE_ROLE_KEY", target: ["production"], provider: "vercel", projectId: "p", repositoryId: "repo-a", connectionFingerprint: "connection-1" },
      ],
    });
    const facts = await loadLiveFacts("u", "repo-a");
    expect(facts[0].id).toBe("vercel:project:p:public-secret:NEXT_PUBLIC_SERVICE_ROLE_KEY");
    expect(facts[0].statement).toContain("browser");
  });

  it("never carries a value, only a name and a scope", async () => {
    loadGraphInput.mockResolvedValue({
      runtimeProvidersRead: ["vercel"],
      runtimeEnvVars: [{ key: "API_KEY", target: ["production"], provider: "vercel", projectId: "p", repositoryId: "repo-a", connectionFingerprint: "connection-1" }],
    });
    const [fact] = await loadLiveFacts("u", "repo-a");
    expect(fact.statement).not.toMatch(/sk_|secret_value|=/);
  });

  it("ignores an ordinary variable that is not credential shaped", async () => {
    loadGraphInput.mockResolvedValue({
      runtimeProvidersRead: ["vercel"],
      runtimeEnvVars: [{ key: "NEXT_PUBLIC_APP_URL", target: ["production"], provider: "vercel", projectId: "p", repositoryId: "repo-a", connectionFingerprint: "connection-1" }],
    });
    expect(await loadLiveFacts("u", "repo-a")).toEqual([]);
  });

  it("keeps identical variable names from different projects distinct", async () => {
    loadGraphInput.mockResolvedValue({ runtimeProvidersRead: ["vercel"], runtimeEnvVars: [
      { key: "API_KEY", target: ["production"], provider: "vercel", projectId: "p1", repositoryId: "repo-a", connectionFingerprint: "connection-1" },
      { key: "API_KEY", target: ["production"], provider: "vercel", projectId: "p2", repositoryId: "repo-a", connectionFingerprint: "connection-1" },
    ] });
    loadVerifiedProviderProjects.mockResolvedValue(new Set(["vercel:p1:connection-1", "vercel:p2:connection-1"]));
    const facts = await loadLiveFacts("u", "repo-a");
    expect(new Set(facts.map((fact) => fact.id)).size).toBe(2);
    expect(facts[0].statement).toContain("project p1");
    expect(facts[1].statement).toContain("project p2");
    expect(facts.every((fact) => !fact.statement.includes("Repository association has not been established"))).toBe(true);
  });

  it("rejects legacy evidence with no repository association", async () => {
    loadGraphInput.mockResolvedValue({ runtimeProvidersRead: ["vercel"], runtimeEnvVars: [
      { key: "API_KEY", target: ["production"], provider: "vercel" },
    ] });
    expect(await loadLiveFacts("u", "repo-a")).toEqual([]);
  });

  it("rejects evidence associated with a different repository", async () => {
    loadGraphInput.mockResolvedValue({ runtimeProvidersRead: ["vercel"], runtimeEnvVars: [
      { key: "API_KEY", target: ["production"], provider: "vercel", projectId: "p", repositoryId: "repo-b" },
    ] });
    expect(await loadLiveFacts("u", "repo-a")).toEqual([]);
  });

  it("rejects embedded association when the persisted mapping is absent", async () => {
    loadGraphInput.mockResolvedValue({ runtimeProvidersRead: ["vercel"], runtimeEnvVars: [
      { key: "API_KEY", target: ["production"], provider: "vercel", projectId: "p", repositoryId: "repo-a", connectionFingerprint: "connection-1" },
    ] });
    loadVerifiedProviderProjects.mockResolvedValue(new Set());
    expect(await loadLiveFacts("u", "repo-a")).toEqual([]);
  });

  it("does not treat a public variable name as proof of browser exposure", async () => {
    loadGraphInput.mockResolvedValue({ runtimeProvidersRead: ["vercel"], runtimeEnvVars: [
      { key: "NEXT_PUBLIC_API_KEY", target: ["preview"], provider: "vercel", projectId: "p", repositoryId: "repo-a", connectionFingerprint: "connection-1" },
    ] });
    expect((await loadLiveFacts("u", "repo-a"))[0].statement).toContain("does not prove its value shipped");
  });

  it.each([undefined, "old-connection"])("excludes missing/old installation identity %s", async (connectionFingerprint) => {
    loadGraphInput.mockResolvedValue({ runtimeProvidersRead: ["vercel"], runtimeEnvVars: [
      { key: "API_KEY", target: ["production"], provider: "vercel", projectId: "p", repositoryId: "repo-a", connectionFingerprint },
    ] });
    expect(await loadLiveFacts("u", "repo-a")).toEqual([]);
  });

  // X1 (2026-10-12): the connected database's own state for the tables this
  // repository's routes reach, admitted only through the repository-bound
  // projection (a confirmed binding on the current connection).
  const bound = (over: Record<string, unknown> = {}) => ({
    correlationScope: "repository-bound",
    routes: [{ path: "/api/x", tables: ["invoices", "notes", "profiles", "drafts"] }],
    scanTables: [{ name: "invoices", rlsEnabled: false }, { name: "notes", rlsEnabled: true },
      { name: "profiles", rlsEnabled: true }, { name: "drafts", rlsEnabled: true }, { name: "audit_log", rlsEnabled: false }],
    policies: [{ schemaname: "public", tablename: "notes", qual: "true", roles: ["anon"] },
      { schemaname: "public", tablename: "profiles", qual: "(auth.uid() = user_id)", roles: ["authenticated"] }],
    ...over,
  });
  const repoScoped = (repoInput: Record<string, unknown>) =>
    loadGraphInput.mockImplementation(async (_u: string, repo?: string) => (repo ? repoInput : {}));

  it("makes the bound database's state citable for the tables a route reaches, open tables first", async () => {
    repoScoped(bound());
    const facts = await loadLiveFacts("u", "repo-a");
    expect(loadGraphInput).toHaveBeenCalledWith("u", "repo-a");
    expect(facts.map((f) => f.id)).toEqual([
      "db:public.invoices:rls-off", "db:public.notes:open-policy",
      "db:public.drafts:rls-filtered", "db:public.profiles:rls-filtered"]);
    expect(facts[0].statement).toMatch(/row level security off on public\.invoices/);
    expect(facts[1].statement).toMatch(/anon/);
  });

  it("states nothing about a database that is not bound to this repository", async () => {
    repoScoped(bound({ correlationScope: "source-only" }));
    expect(await loadLiveFacts("u", "repo-a")).toEqual([]);
  });

  it("states nothing where the rules were never read", async () => {
    repoScoped(bound({ policies: undefined, scanTables: [{ name: "notes", rlsEnabled: true }] }));
    expect(await loadLiveFacts("u", "repo-a")).toEqual([]);
  });

  it("keeps the audit running when the bound database cannot be read", async () => {
    loadGraphInput.mockImplementation(async (_u: string, repo?: string) => {
      if (repo) throw new Error("Graph facts could not be read");
      return { runtimeProvidersRead: ["vercel"], runtimeEnvVars: [] };
    });
    const log = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      expect(await loadLiveFacts("u", "repo-a")).toEqual([]);
      expect(log).toHaveBeenCalledOnce();
    } finally { log.mockRestore(); }
  });

  it("excludes optional runtime context without breaking source audits on a mapping read failure", async () => {
    loadGraphInput.mockResolvedValue({ runtimeProvidersRead: ["vercel"], runtimeEnvVars: [] });
    loadVerifiedProviderProjects.mockRejectedValue(new Error("migration missing"));
    const log = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      expect(await loadLiveFacts("u", "repo-a")).toEqual([]);
      expect(log).toHaveBeenCalledOnce();
    } finally { log.mockRestore(); }
  });
});
