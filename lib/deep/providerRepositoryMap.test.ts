import { beforeEach, describe, expect, it, vi } from "vitest";

const reads = { repositories: vi.fn(), user_profiles: vi.fn(), provider_repository_links: vi.fn() };
const filters = vi.fn();
const upsert = vi.fn();
const deleteIn = vi.fn();
vi.mock("@/lib/supabase", () => ({
  getSupabaseAdmin: () => ({
    from: (table: keyof typeof reads) => {
      const query = {
        eq: (column: string, value: unknown) => { filters(table, column, value); return query; },
        maybeSingle: () => reads[table](),
        then: (resolve: (value: unknown) => unknown, reject: (error: unknown) => unknown) => reads[table]().then(resolve, reject),
        in: deleteIn,
      };
      return { select: () => query, upsert, delete: () => query };
    },
  }),
}));

const { syncVercelRepositoryLinks, loadVerifiedProviderProjects } = await import("./providerRepositoryMap");
const fingerprint = "a".repeat(64);
const project = { id: "p", name: "web", gitRepository: { type: "github" as const, fullName: "acme/web", repoId: "42" } };
const selected = { id: "repo-a", full_name: "Acme/Web", github_repo_id: 42 };

beforeEach(() => {
  filters.mockReset();
  upsert.mockReset().mockResolvedValue({ error: null });
  deleteIn.mockReset().mockResolvedValue({ error: null });
  reads.repositories.mockReset().mockResolvedValue({ data: [selected], error: null });
  reads.user_profiles.mockReset().mockResolvedValue({ data: { vercel_access_token_encrypted: "cipher", vercel_connection_epoch: fingerprint }, error: null });
  reads.provider_repository_links.mockReset().mockResolvedValue({ data: [], error: null });
});

describe("syncVercelRepositoryLinks", () => {
  it("maps only an explicit GitHub link to the tenant's selected repository", async () => {
    expect(await syncVercelRepositoryLinks("u", [project], fingerprint)).toEqual(new Map([["p", "repo-a"]]));
    expect(filters.mock.calls).toEqual([["repositories", "user_id", "u"], ["repositories", "selected", true]]);
    expect(upsert).toHaveBeenCalledWith([expect.objectContaining({
      user_id: "u", repository_id: "repo-a", provider: "vercel", provider_project_id: "p",
      provider_repository: "acme/web", verification_method: "provider_git_link", connection_fingerprint: fingerprint,
    })], { onConflict: "user_id,provider,provider_project_id" });
    expect(JSON.stringify(upsert.mock.calls)).not.toContain('"cipher"');
  });

  it("rejects matching names with disagreeing GitHub ids", async () => {
    reads.repositories.mockResolvedValue({ data: [{ ...selected, github_repo_id: 99 }], error: null });
    expect((await syncVercelRepositoryLinks("u", [project], fingerprint)).size).toBe(0);
    expect(upsert).not.toHaveBeenCalled();
    expect(deleteIn).toHaveBeenCalledWith("provider_project_id", ["p"]);
  });

  it("does not guess from project names or ambiguous repository identities", async () => {
    reads.repositories.mockResolvedValue({ data: [selected, { ...selected, id: "repo-b", full_name: "acme/web" }], error: null });
    expect((await syncVercelRepositoryLinks("u", [project, { id: "p2", name: "Acme/Web" }], fingerprint)).size).toBe(0);
    expect(upsert).not.toHaveBeenCalled();
  });

  it("clears observed invalid mappings, not unseen/paginated projects", async () => {
    await syncVercelRepositoryLinks("u", [{ id: "p", name: "unlinked" }], fingerprint);
    expect(filters).toHaveBeenCalledWith("provider_repository_links", "user_id", "u");
    expect(filters).toHaveBeenCalledWith("provider_repository_links", "provider", "vercel");
    expect(deleteIn).toHaveBeenCalledWith("provider_project_id", ["p"]);
  });

  it("fails closed on selected repository read failure", async () => {
    reads.repositories.mockResolvedValue({ data: null, error: { message: "read failed" } });
    await expect(syncVercelRepositoryLinks("u", [project], fingerprint)).rejects.toThrow("could not be read");
    expect(upsert).not.toHaveBeenCalled();
  });

  it("fails closed on persistence failure", async () => {
    upsert.mockResolvedValue({ error: { message: "write failed" } });
    await expect(syncVercelRepositoryLinks("u", [project], fingerprint)).rejects.toThrow("could not be saved");
  });

  it("fails closed on stale mapping cleanup failure", async () => {
    deleteIn.mockResolvedValue({ error: { message: "delete failed" } });
    await expect(syncVercelRepositoryLinks("u", [{ id: "p", name: "unlinked" }], fingerprint)).rejects.toThrow("could not be cleared");
  });
});

describe("loadVerifiedProviderProjects", () => {
  beforeEach(() => {
    reads.repositories.mockResolvedValue({ data: { id: "repo-a" }, error: null });
  });
  it("requires tenant, selected repo, persisted project and current installation", async () => {
    reads.provider_repository_links.mockResolvedValue({ data: [
      { provider: "vercel", provider_project_id: "p", connection_fingerprint: fingerprint },
      { provider: "vercel", provider_project_id: "old", connection_fingerprint: "b".repeat(64) },
      { provider: "other", provider_project_id: "p", connection_fingerprint: fingerprint },
    ], error: null });
    expect(await loadVerifiedProviderProjects("u", "repo-a")).toEqual(new Set([`vercel:p:${fingerprint}`]));
    expect(filters.mock.calls).toEqual([
      ["user_profiles", "id", "u"], ["repositories", "user_id", "u"],
      ["repositories", "id", "repo-a"], ["repositories", "selected", true],
      ["provider_repository_links", "user_id", "u"], ["provider_repository_links", "repository_id", "repo-a"],
    ]);
  });

  it.each(["disconnected", "unselected"])("rejects stale links when %s", async (state) => {
    if (state === "disconnected") reads.user_profiles.mockResolvedValue({ data: { vercel_access_token_encrypted: null }, error: null });
    else reads.repositories.mockResolvedValue({ data: null, error: null });
    expect(await loadVerifiedProviderProjects("u", "repo-a")).toEqual(new Set());
    expect(reads.provider_repository_links).not.toHaveBeenCalled();
  });

  it("keeps links across a token re-encryption that preserved the epoch", async () => {
    reads.user_profiles.mockResolvedValue({ data: { vercel_access_token_encrypted: "re-encrypted", vercel_connection_epoch: fingerprint }, error: null });
    reads.provider_repository_links.mockResolvedValue({ data: [{ provider: "vercel", provider_project_id: "p", connection_fingerprint: fingerprint }], error: null });
    expect(await loadVerifiedProviderProjects("u", "repo-a")).toEqual(new Set([`vercel:p:${fingerprint}`]));
  });

  it("rejects links from before a reconnect", async () => {
    reads.user_profiles.mockResolvedValue({ data: { vercel_access_token_encrypted: "new-cipher", vercel_connection_epoch: "c".repeat(64) }, error: null });
    reads.provider_repository_links.mockResolvedValue({ data: [{ provider: "vercel", provider_project_id: "p", connection_fingerprint: fingerprint }], error: null });
    expect(await loadVerifiedProviderProjects("u", "repo-a")).toEqual(new Set());
  });

  it.each(["repositories", "user_profiles", "provider_repository_links"] as const)("fails closed on %s read failure", async (table) => {
    reads[table].mockResolvedValue({ data: null, error: { message: "read failed" } });
    await expect(loadVerifiedProviderProjects("u", "repo-a")).rejects.toThrow("could not be read");
  });
});
