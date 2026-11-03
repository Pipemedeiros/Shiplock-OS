import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  gate: vi.fn(), profile: vi.fn(), repositories: vi.fn(), links: vi.fn(), write: vi.fn(), filters: vi.fn(), payload: vi.fn(),
}));
vi.mock("@/lib/deep/proGate", () => ({ requireProUser: mocks.gate }));
vi.mock("@/lib/supabase", () => ({ getSupabaseAdmin: () => ({ from: (table: string) => {
  let mutation: "upsert" | "delete" | undefined;
  const read = () => mutation ? mocks.write(mutation) :
    table === "user_profiles" ? mocks.profile() : table === "repositories" ? mocks.repositories() : mocks.links();
  const query = {
    select: () => query,
    eq: (key: string, value: unknown) => { mocks.filters(table, key, value); return query; },
    maybeSingle: read, single: read,
    then: (resolve: (value: unknown) => unknown, reject: (error: unknown) => unknown) => read().then(resolve, reject),
    upsert: (row: unknown, options: unknown) => { mutation = "upsert"; mocks.payload(row, options); return query; },
    delete: () => { mutation = "delete"; return query; },
  };
  return query;
} }) }));

import { GET, POST } from "./route";

const userId = "11111111-1111-4111-8111-111111111111";
const repositoryId = "22222222-2222-4222-8222-222222222222";
const at = "2026-09-17T10:00:00.000Z";
const connectedAt = "2026-09-17T09:00:00.000Z";
const fingerprint = "d".repeat(64);
const profile = { postgres_dsn_encrypted: "stored-encrypted-dsn", postgres_connection_epoch: fingerprint, github_installation_id: 42, github_connected_at: connectedAt };
const repository = { id: repositoryId, full_name: "acme/app", github_repo_id: 7 };
const confirmation = { action: "confirm", confirmed: true, repositoryId, expectedConnectionFingerprint: fingerprint,
  expectedInstallationId: "42", expectedGithubConnectedAt: connectedAt, expectedRepositoryFullName: "acme/app", expectedGithubRepositoryId: "7" };
const stored = { user_id: userId, repository_id: repositoryId, collector: "postgres-direct", connection_fingerprint: fingerprint,
  github_installation_id: "42", github_connected_at: connectedAt, repository_full_name: "acme/app", github_repo_id: "7",
  confirmation_method: "customer_confirmed", confirmed_at: at };
function request(body: unknown = confirmation, headers: Record<string, string> = {}) {
  return new Request("https://shiplock.dev/api/deep/postgres/repository", { method: "POST",
    headers: { Origin: "https://shiplock.dev", "Content-Type": "application/json", ...headers }, body: JSON.stringify(body) });
}

beforeEach(() => {
  vi.spyOn(Date, "now").mockReturnValue(Date.parse(at));
  mocks.gate.mockReset().mockResolvedValue({ userId, email: null });
  mocks.profile.mockReset().mockResolvedValue({ data: profile, error: null });
  mocks.repositories.mockReset().mockResolvedValue({ data: [repository], error: null });
  mocks.links.mockReset().mockResolvedValue({ data: [], error: null });
  mocks.write.mockReset().mockResolvedValue({ data: stored, error: null });
  mocks.filters.mockReset(); mocks.payload.mockReset();
});
afterEach(() => vi.restoreAllMocks());

describe("explicit direct-Postgres repository confirmation", () => {
  it("offers only selected repositories and opaque current context, never the encrypted DSN", async () => {
    const response = await GET();
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ available: true, databaseDisplay: null, connectionFingerprint: fingerprint, installationId: "42",
      githubConnectedAt: connectedAt, repositories: [{ id: repositoryId, fullName: "acme/app", githubRepoId: "7" }], bindings: [] });
    expect(mocks.filters).toHaveBeenCalledWith("user_profiles", "id", userId);
    expect(mocks.filters).toHaveBeenCalledWith("repositories", "user_id", userId);
    expect(mocks.filters).toHaveBeenCalledWith("repositories", "selected", true);
    expect(mocks.filters).toHaveBeenCalledWith("database_repository_bindings", "user_id", userId);
    expect(mocks.write).not.toHaveBeenCalled();
  });

  it("persists only server-derived identity after explicit confirmation and checks the receipt", async () => {
    const response = await POST(request());
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ ok: true, method: "customer_confirmed" });
    expect(mocks.payload).toHaveBeenCalledWith(stored, { onConflict: "user_id,collector,repository_id" });
  });

  it("returns the current stored display label, not the encrypted credential or unrelated profile fields", async () => {
    mocks.profile.mockResolvedValue({ data: { ...profile, postgres_display: "db.example/app", stripe_customer_id: "private-billing" }, error: null });
    const body = await (await GET()).json();
    expect(body.databaseDisplay).toBe("db.example/app");
    expect(JSON.stringify(body)).not.toContain("stored-encrypted-dsn");
    expect(JSON.stringify(body)).not.toContain("private-billing");
    mocks.profile.mockResolvedValue({ data: { ...profile, postgres_display: "new.example/app" }, error: null });
    expect((await (await GET()).json()).databaseDisplay).toBe("new.example/app");
    expect(mocks.write).not.toHaveBeenCalled();
  });

  it.each(["confirm", "remove"])("requires explicit approval for %s", async (action) => {
    const response = await POST(request({ ...confirmation, action, confirmed: false }));
    expect(response.status).toBe(400); expect(mocks.write).not.toHaveBeenCalled();
  });

  it.each([
    { expectedConnectionFingerprint: "a".repeat(64) }, { expectedInstallationId: "43" },
    { expectedGithubConnectedAt: "2026-09-17T08:00:00.000Z" }, { expectedRepositoryFullName: "acme/other" },
    { repositoryId: "33333333-3333-4333-8333-333333333333" },
    { expectedGithubRepositoryId: "8" },
  ])("refuses stale or unselected confirmation context: %j", async (override) => {
    expect((await POST(request({ ...confirmation, ...override }))).status).toBe(409);
    expect(mocks.write).not.toHaveBeenCalled();
  });

  it.each([null, { ...profile, postgres_dsn_encrypted: null }, { ...profile, github_installation_id: null },
    { ...profile, github_connected_at: "2026-09-18T00:00:00Z" }, { ...profile, postgres_dsn_encrypted: 42 }])(
    "does not offer a binding when connection context is missing or malformed: %j", async (data) => {
      mocks.profile.mockResolvedValue({ data, error: null });
      expect(await (await GET()).json()).toEqual({ available: false, repositories: [], bindings: [] });
      expect((await POST(request())).status).toBe(409); expect(mocks.write).not.toHaveBeenCalled();
    });

  it.each(["user", "method", "fingerprint", "repo", "installation", "epoch", "numeric-id", "date"])(
    "excludes a stale/inconsistent stored binding: %s", async (kind) => {
      const overrides = {
        user: { user_id: "other-user" }, method: { confirmation_method: "provider_verified" },
        fingerprint: { connection_fingerprint: "a".repeat(64) }, repo: { repository_full_name: "acme/old" },
        installation: { github_installation_id: "43" }, epoch: { github_connected_at: "2026-09-16T09:00:00Z" },
        "numeric-id": { github_repo_id: "8" }, date: { confirmed_at: "2026-09-18T00:00:00Z" },
      };
      mocks.links.mockResolvedValue({ data: [{ ...stored, ...overrides[kind as keyof typeof overrides] }], error: null });
      expect((await (await GET()).json()).bindings).toEqual([]);
    });

  it("labels the current binding as customer-confirmed, not provider or deployment proof", async () => {
    mocks.links.mockResolvedValue({ data: [stored], error: null });
    expect((await (await GET()).json()).bindings).toEqual([{ repositoryId, method: "customer_confirmed", confirmedAt: at }]);
  });

  it("refuses ambiguous selected repositories and duplicate stored bindings", async () => {
    mocks.repositories.mockResolvedValue({ data: [repository, { ...repository, id: "33333333-3333-4333-8333-333333333333" }], error: null });
    expect((await POST(request())).status).toBe(409); expect(mocks.write).not.toHaveBeenCalled();
    mocks.repositories.mockResolvedValue({ data: [repository], error: null });
    mocks.links.mockResolvedValue({ data: [stored, { ...stored, confirmation_method: "malformed" }], error: null });
    expect((await (await GET()).json()).bindings).toEqual([]);
  });

  it.each(["profile", "repositories", "links"])("fails closed on a returned %s read error", async (read) => {
    mocks[read as "profile" | "repositories" | "links"].mockResolvedValue({ data: null, error: { message: "private-error" } });
    const response = await GET(); expect(response.status).toBe(503);
    expect(await response.text()).not.toContain("private-error"); expect(mocks.write).not.toHaveBeenCalled();
  });

  it("does not claim successful persistence on a returned write error or absent receipt", async () => {
    for (const result of [{ data: null, error: { message: "private-error" } }, { data: null, error: null },
      { data: { ...stored, repository_id: "wrong-repo" }, error: null }]) {
      mocks.write.mockResolvedValue(result);
      const response = await POST(request()); expect(response.status).toBe(503);
      expect(await response.text()).not.toContain("private-error");
    }
  });

  it("accepts equivalent database timestamp serialization in a valid receipt", async () => {
    mocks.write.mockResolvedValue({ data: { ...stored, confirmed_at: "2026-09-17T10:00:00+00:00" }, error: null });
    expect((await POST(request())).status).toBe(200);
  });

  it("removes only the expressly confirmed current user/repository/connection binding", async () => {
    mocks.write.mockResolvedValue({ data: [{ repository_id: repositoryId }], error: null });
    expect((await POST(request({ ...confirmation, action: "remove" }))).status).toBe(200);
    expect(mocks.filters).toHaveBeenCalledWith("database_repository_bindings", "user_id", userId);
    expect(mocks.filters).toHaveBeenCalledWith("database_repository_bindings", "repository_id", repositoryId);
    expect(mocks.filters).toHaveBeenCalledWith("database_repository_bindings", "collector", "postgres-direct");
    expect(mocks.filters).toHaveBeenCalledWith("database_repository_bindings", "connection_fingerprint", fingerprint);
    expect(mocks.payload).not.toHaveBeenCalled();
  });

  it.each([null, "https://evil.example", "null"])("refuses missing/cross-site origins: %s", async (origin) => {
    const req = request();
    if (origin === null) req.headers.delete("Origin");
    else req.headers.set("Origin", origin);
    expect((await POST(req)).status).toBe(403); expect(mocks.write).not.toHaveBeenCalled();
  });

  it("refuses non-JSON, unknown fields, malformed JSON and oversized request bodies", async () => {
    expect((await POST(request(confirmation, { "Content-Type": "text/plain" }))).status).toBe(415);
    expect((await POST(request({ ...confirmation, userId: "other-user" }))).status).toBe(400);
    const cancel = vi.fn();
    const init = { method: "POST", headers: { Origin: "https://shiplock.dev", "Content-Type": "application/json" },
      body: new ReadableStream({ start(controller) { controller.enqueue(new TextEncoder().encode("x".repeat(8193))); }, cancel }),
      duplex: "half" };
    const req = new Request("https://shiplock.dev/api/deep/postgres/repository", init);
    expect((await POST(req)).status).toBe(400);
    expect(cancel).toHaveBeenCalledTimes(1);
    const bad = new Request("https://shiplock.dev/api/deep/postgres/repository", { method: "POST",
      headers: { Origin: "https://shiplock.dev", "Content-Type": "application/json" }, body: "{" });
    expect((await POST(bad)).status).toBe(400); expect(mocks.write).not.toHaveBeenCalled();
  });

  it("requires the existing authenticated product gate for reads and writes", async () => {
    mocks.gate.mockResolvedValue(null);
    expect((await GET()).status).toBe(403); expect((await POST(request())).status).toBe(403);
    expect(mocks.profile).not.toHaveBeenCalled(); expect(mocks.write).not.toHaveBeenCalled();
  });

  it("contains thrown storage errors without logging raw credentials", async () => {
    const log = vi.spyOn(console, "error").mockImplementation(() => {});
    mocks.write.mockRejectedValue(new Error("stored-encrypted-dsn private-error"));
    const response = await POST(request()); expect(response.status).toBe(503);
    expect(await response.text()).not.toContain("stored-encrypted-dsn");
    expect(JSON.stringify(log.mock.calls)).not.toContain("stored-encrypted-dsn");
  });

  it.each([{ postgres_dsn_encrypted: "replacement", postgres_connection_epoch: "f".repeat(64) }, { github_installation_id: null },
    { github_connected_at: "2026-09-17T09:30:00.000Z" }])(
    "does not acknowledge confirmation when context changes during persistence: %j", async (change) => {
      mocks.profile.mockResolvedValueOnce({ data: profile, error: null })
        .mockResolvedValue({ data: { ...profile, ...change }, error: null });
      expect((await POST(request())).status).toBe(409);
      expect(mocks.payload).toHaveBeenCalledTimes(1);
      // The stored old-context row is not admitted against the new connection.
      mocks.links.mockResolvedValue({ data: [stored], error: null });
      expect((await (await GET()).json()).bindings).toEqual([]);
    });

  it.each([{ changed: [] }, { changed: [{ ...repository, full_name: "acme/renamed" }] }, { changed: [{ ...repository, github_repo_id: 8 }] }])(
    "does not acknowledge confirmation when selection/identity changes during persistence: %j", async ({ changed }) => {
      mocks.repositories.mockResolvedValueOnce({ data: [repository], error: null }).mockResolvedValue({ data: changed, error: null });
      expect((await POST(request())).status).toBe(409);
    });

  it.each([{ data: null }, { data: [{ ...repository, id: "invalid" }] }, { data: [repository, { ...repository, full_name: "acme/renamed" }] }])(
    "refuses malformed or duplicated selected identity: %j", async ({ data }) => {
      mocks.repositories.mockResolvedValue({ data, error: null });
      expect((await POST(request())).status).toBe(409); expect(mocks.write).not.toHaveBeenCalled();
    });

  it("supports a legacy repository without inventing a GitHub numeric ID", async () => {
    mocks.repositories.mockResolvedValue({ data: [{ ...repository, github_repo_id: null }], error: null });
    mocks.write.mockResolvedValue({ data: { ...stored, github_repo_id: null }, error: null });
    expect((await POST(request({ ...confirmation, expectedGithubRepositoryId: null }))).status).toBe(200);
    expect(mocks.payload.mock.calls[0][0].github_repo_id).toBeNull();
  });

  it("treats removal as idempotent but never acknowledges a returned delete error", async () => {
    mocks.write.mockResolvedValue({ data: [], error: null });
    expect((await POST(request({ ...confirmation, action: "remove" }))).status).toBe(200);
    mocks.write.mockResolvedValue({ data: [], error: { message: "private-error" } });
    expect((await POST(request({ ...confirmation, action: "remove" }))).status).toBe(503);
  });

  it("does not write after a failed confirmation-context read", async () => {
    mocks.profile.mockResolvedValue({ data: profile, error: { message: "private-error" } });
    expect((await POST(request())).status).toBe(503); expect(mocks.write).not.toHaveBeenCalled();
  });

  it("does not acknowledge a write when the post-write context read fails", async () => {
    mocks.profile.mockResolvedValueOnce({ data: profile, error: null })
      .mockResolvedValue({ data: null, error: { message: "private-error" } });
    expect((await POST(request())).status).toBe(503);
    expect(mocks.payload).toHaveBeenCalledTimes(1);
  });
});
