import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({ gate: vi.fn(), profile: vi.fn(), repositories: vi.fn(), links: vi.fn(),
  write: vi.fn(), filters: vi.fn(), payload: vi.fn(), selects: vi.fn() }));
vi.mock("@/lib/deep/proGate", () => ({ requireProUser: mocks.gate }));
vi.mock("@/lib/supabase", () => ({ getSupabaseAdmin: () => ({ from: (table: string) => {
  if (!["user_profiles", "repositories", "database_repository_bindings"].includes(table)) throw new Error("Unexpected table");
  let mutation: "upsert" | "delete" | undefined;
  const read = () => mutation ? mocks.write(mutation) : table === "user_profiles" ? mocks.profile() : table === "repositories" ? mocks.repositories() : mocks.links();
  const query = {
    select: (columns: string) => { mocks.selects(table, columns); return query; },
    eq: (key: string, value: unknown) => { mocks.filters(table, "eq", key, value); return query; },
    is: (key: string, value: unknown) => { mocks.filters(table, "is", key, value); return query; },
    maybeSingle: read, single: read,
    then: (resolve: (value: unknown) => unknown, reject: (error: unknown) => unknown) => read().then(resolve, reject),
    upsert: (row: unknown, options: unknown) => { mutation = "upsert"; mocks.payload(row, options); return query; },
    delete: () => { mutation = "delete"; return query; },
  };
  return query;
} }) }));

import { GET, POST } from "./route";

const userId = "11111111-1111-4111-8111-111111111111", repositoryId = "22222222-2222-4222-8222-222222222222";
const at = "2026-09-17T10:00:00.000Z", connectedAt = "2026-09-17T09:00:00.000Z";
const ref = "project-a", url = `https://${ref}.supabase.co`, fingerprint = "a".repeat(64);
const profile = { github_installation_id: 42, github_connected_at: connectedAt,
  supabase_mgmt_token_encrypted: "shared-encrypted", supabase_mgmt_connection_epoch: fingerprint, supabase_mgmt_project_ref: ref,
  monitored_anon_key_encrypted: "shared-encrypted", supabase_endpoint_connection_epoch: fingerprint, monitored_project_url: url, postgres_dsn_encrypted: "private-direct-decoy" };
const repository = { id: repositoryId, full_name: "acme/app", github_repo_id: 7 };
const fixtures = [
  { collector: "supabase-management", credentialField: "supabase_mgmt_token_encrypted", epochField: "supabase_mgmt_connection_epoch", projectField: "supabase_mgmt_project_ref", endpoint: null },
  { collector: "supabase-scan", credentialField: "monitored_anon_key_encrypted", epochField: "supabase_endpoint_connection_epoch", projectField: "monitored_project_url", endpoint: url },
] as const;
function request(body: unknown, headers: Record<string, string> = {}) {
  return new Request("https://shiplock.dev/api/deep/supabase/repository", { method: "POST",
    headers: { Origin: "https://shiplock.dev", "Content-Type": "application/json", ...headers }, body: JSON.stringify(body) });
}
const get = (collector: string) => GET(new Request(`https://shiplock.dev/api/deep/supabase/repository?collector=${collector}`));

beforeEach(() => {
  vi.spyOn(Date, "now").mockReturnValue(Date.parse(at));
  vi.spyOn(globalThis, "fetch").mockRejectedValue(new Error("Unexpected outbound request"));
  mocks.gate.mockReset().mockResolvedValue({ userId, email: null });
  mocks.profile.mockReset().mockResolvedValue({ data: profile, error: null });
  mocks.repositories.mockReset().mockResolvedValue({ data: [repository], error: null });
  mocks.links.mockReset().mockResolvedValue({ data: [], error: null });
  mocks.write.mockReset(); mocks.filters.mockReset(); mocks.payload.mockReset(); mocks.selects.mockReset();
});
afterEach(() => {
  try { expect(globalThis.fetch).not.toHaveBeenCalled(); }
  finally { vi.restoreAllMocks(); }
});

describe.each(fixtures)("$collector confirmation", ({ collector, credentialField, epochField, projectField, endpoint }) => {
  const confirmation = { action: "confirm", confirmed: true, collector, repositoryId, expectedProjectRef: ref, expectedEndpointUrl: endpoint,
    expectedConnectionFingerprint: fingerprint, expectedInstallationId: "42", expectedGithubConnectedAt: connectedAt,
    expectedRepositoryFullName: "acme/app", expectedGithubRepositoryId: "7" };
  const stored = { user_id: userId, repository_id: repositoryId, collector, project_ref: ref, endpoint_url: endpoint,
    connection_fingerprint: fingerprint, github_installation_id: "42", github_connected_at: connectedAt,
    repository_full_name: "acme/app", github_repo_id: "7", confirmation_method: "customer_confirmed", confirmed_at: at };

  beforeEach(() => { mocks.write.mockResolvedValue({ data: stored, error: null }); });

  it("returns only this transport's current context and scopes every read to this user/selection", async () => {
    const response = await get(collector); expect(response.status).toBe(200); expect(response.headers.get("cache-control")).toBe("no-store");
    const body = await response.json();
    expect(body).toEqual({ available: true, collector, projectRef: ref, endpointUrl: endpoint, connectionFingerprint: fingerprint,
      installationId: "42", githubConnectedAt: connectedAt, repositories: [{ id: repositoryId, fullName: "acme/app", githubRepoId: "7" }], bindings: [] });
    expect(JSON.stringify(body)).not.toContain("shared-encrypted"); expect(JSON.stringify(body)).not.toContain("private-direct-decoy");
    expect(mocks.filters).toHaveBeenCalledWith("user_profiles", "eq", "id", userId);
    expect(mocks.filters).toHaveBeenCalledWith("repositories", "eq", "user_id", userId);
    expect(mocks.filters).toHaveBeenCalledWith("repositories", "eq", "selected", true);
    expect(mocks.filters).toHaveBeenCalledWith("database_repository_bindings", "eq", "user_id", userId);
    expect(mocks.filters).toHaveBeenCalledWith("database_repository_bindings", "eq", "collector", collector);
    const fields = mocks.selects.mock.calls.find(([table]) => table === "user_profiles")?.[1];
    expect(fields).toContain(credentialField); expect(fields).not.toContain("postgres_dsn_encrypted");
    expect(fields).not.toContain(collector === "supabase-management" ? "monitored_anon_key_encrypted" : "supabase_mgmt_token_encrypted");
    expect(mocks.write).not.toHaveBeenCalled();
  });

  it("persists exactly the expressly approved server-derived transport identity with checked receipt", async () => {
    expect((await POST(request(confirmation))).status).toBe(200);
    expect(mocks.payload).toHaveBeenCalledWith(stored, { onConflict: "user_id,collector,repository_id" });
  });

  it("labels admitted associations as customer decisions, not deployment/security proof", async () => {
    mocks.links.mockResolvedValue({ data: [stored], error: null });
    expect((await (await get(collector)).json()).bindings).toEqual([{ repositoryId, method: "customer_confirmed", confirmedAt: at }]);
  });

  it("does not inherit a well-formed other-transport confirmation even for identical project and ciphertext", async () => {
    const other = { ...stored, collector: collector === "supabase-management" ? "supabase-scan" : "supabase-management", endpoint_url: endpoint === null ? url : null };
    mocks.links.mockResolvedValue({ data: [other], error: null });
    expect((await (await get(collector)).json()).bindings).toEqual([]); expect(mocks.write).not.toHaveBeenCalled();
  });

  it("unrelated transport reconnects do not change this transport's customer decision", async () => {
    const other = collector === "supabase-management" ? { monitored_project_url: "https://project-b.supabase.co", monitored_anon_key_encrypted: "other-key" }
      : { supabase_mgmt_project_ref: "project-b", supabase_mgmt_token_encrypted: "other-key" };
    mocks.profile.mockResolvedValue({ data: { ...profile, ...other }, error: null });
    expect((await POST(request(confirmation))).status).toBe(200);
    mocks.links.mockResolvedValue({ data: [stored], error: null });
    expect((await (await get(collector)).json()).bindings).toHaveLength(1);
  });

  it.each([{ expectedProjectRef: "project-b" }, { expectedConnectionFingerprint: "b".repeat(64) }, { expectedInstallationId: "43" },
    { expectedGithubConnectedAt: "2026-09-17T08:00:00Z" }, { expectedRepositoryFullName: "acme/other" }, { expectedGithubRepositoryId: "8" },
    { repositoryId: "33333333-3333-4333-8333-333333333333" }])("refuses stale/changed approval identity: %j", async (change) => {
    const body = { ...confirmation, ...change,
      ...(endpoint && "expectedProjectRef" in change ? { expectedEndpointUrl: `https://${change.expectedProjectRef}.supabase.co` } : {}) };
    expect((await POST(request(body))).status).toBe(409); expect(mocks.write).not.toHaveBeenCalled();
  });

  it.each(["user", "collector", "project", "endpoint", "credential", "method", "installation", "epoch", "numeric-id", "name", "future-date", "old-date"])(
    "excludes inconsistent stored association: %s", async (kind) => {
      const changes: Record<string, unknown> = { user: { user_id: "33333333-3333-4333-8333-333333333333" },
        collector: { collector: collector === "supabase-management" ? "supabase-scan" : "supabase-management" },
        project: { project_ref: "project-b" }, endpoint: { endpoint_url: endpoint ? "https://project-b.supabase.co" : url },
        credential: { connection_fingerprint: "b".repeat(64) }, method: { confirmation_method: "provider_verified" },
        installation: { github_installation_id: "43" }, epoch: { github_connected_at: "2026-09-17T08:00:00Z" },
        "numeric-id": { github_repo_id: "8" }, name: { repository_full_name: "acme/other" },
        "future-date": { confirmed_at: "2026-09-18T00:00:00Z" }, "old-date": { confirmed_at: "2026-09-16T00:00:00Z" } };
      mocks.links.mockResolvedValue({ data: [{ ...stored, ...changes[kind] as object }], error: null });
      expect((await (await get(collector)).json()).bindings).toEqual([]);
    });

  it.each([null, "", 42])("never borrows the other transport's credential when its own is %j", async (value) => {
    mocks.profile.mockResolvedValue({ data: { ...profile, [credentialField]: value }, error: null });
    expect(await (await get(collector)).json()).toEqual({ available: false, collector, repositories: [], bindings: [] });
    expect((await POST(request(confirmation))).status).toBe(409); expect(mocks.write).not.toHaveBeenCalled();
  });

  it.each([null, "", " bad-project "])("requires its own valid project context: %j", async (value) => {
    mocks.profile.mockResolvedValue({ data: { ...profile, [projectField]: value }, error: null });
    expect((await (await get(collector)).json()).available).toBe(false);
    expect((await POST(request(confirmation))).status).toBe(409); expect(mocks.write).not.toHaveBeenCalled();
  });

  it("rejects ambiguous repository IDs/names/numeric IDs and duplicate binding rows", async () => {
    mocks.repositories.mockResolvedValue({ data: [repository, { ...repository, id: "33333333-3333-4333-8333-333333333333", full_name: "acme/renamed" }], error: null });
    expect((await POST(request(confirmation))).status).toBe(409); expect(mocks.write).not.toHaveBeenCalled();
    mocks.repositories.mockResolvedValue({ data: [repository], error: null });
    mocks.links.mockResolvedValue({ data: [stored, stored], error: null }); expect((await (await get(collector)).json()).bindings).toEqual([]);
  });

  it.each(["profile", "repositories", "links"] as const)("fails closed on a returned %s read error", async (key) => {
    mocks[key].mockResolvedValue({ data: null, error: { message: "private-error" } });
    const response = await get(collector); expect(response.status).toBe(503); expect(await response.text()).not.toContain("private-error");
  });

  it.each(["error", "missing", "wrong-transport", "wrong-project"])("never reports persistence with %s receipt", async (kind) => {
    const data = kind === "missing" ? null : { ...stored, ...(kind === "wrong-transport" ? { collector: "postgres-direct" } : kind === "wrong-project" ? { project_ref: "project-b" } : {}) };
    mocks.write.mockResolvedValue({ data, error: kind === "error" ? { message: "private-error" } : null });
    const response = await POST(request(confirmation)); expect(response.status).toBe(503); expect(await response.text()).not.toContain("private-error");
  });

  it("removes only this user/repository/transport/project/credential/epoch identity", async () => {
    mocks.write.mockResolvedValue({ data: [{ repository_id: repositoryId }], error: null });
    expect((await POST(request({ ...confirmation, action: "remove" }))).status).toBe(200);
    for (const [field, value] of Object.entries({ user_id: userId, repository_id: repositoryId, collector, project_ref: ref,
      connection_fingerprint: fingerprint, github_installation_id: "42", github_connected_at: connectedAt })) {
      expect(mocks.filters).toHaveBeenCalledWith("database_repository_bindings", "eq", field, value);
    }
    expect(mocks.filters).toHaveBeenCalledWith("database_repository_bindings", endpoint === null ? "is" : "eq", "endpoint_url", endpoint);
    expect(mocks.payload).not.toHaveBeenCalled();
  });

  it("removal is idempotent but returned errors/mismatched rows are not success", async () => {
    for (const result of [{ data: [], error: null }, { data: [], error: { message: "private-error" } }, { data: [{ repository_id: "wrong" }], error: null }]) {
      mocks.write.mockResolvedValue(result); expect((await POST(request({ ...confirmation, action: "remove" }))).status).toBe(result.error || result.data.length ? 503 : 200);
    }
  });

  it.each(["project", "credential", "github"])("does not acknowledge a %s change during persistence", async (kind) => {
    const change = kind === "project" ? { [projectField]: endpoint ? "https://project-b.supabase.co" : "project-b" }
      // A reconnect mints a new epoch; a ciphertext-only change is a refresh.
      : kind === "credential" ? { [credentialField]: "replacement", [epochField]: "f".repeat(64) } : { github_connected_at: "2026-09-17T09:30:00Z" };
    mocks.profile.mockResolvedValueOnce({ data: profile, error: null }).mockResolvedValue({ data: { ...profile, ...change }, error: null });
    expect((await POST(request(confirmation))).status).toBe(409);
    mocks.links.mockResolvedValue({ data: [stored], error: null }); expect((await (await get(collector)).json()).bindings).toEqual([]);
  });

  it("acknowledges a refresh that re-encrypted the credential but kept the epoch", async () => {
    mocks.profile.mockResolvedValueOnce({ data: profile, error: null })
      .mockResolvedValue({ data: { ...profile, [credentialField]: "refreshed" }, error: null });
    expect((await POST(request(confirmation))).status).toBe(200);
  });

  it("also rechecks identity after removal without silently retrying/rolling back", async () => {
    mocks.write.mockResolvedValue({ data: [], error: null });
    mocks.repositories.mockResolvedValueOnce({ data: [repository], error: null }).mockResolvedValue({ data: [], error: null });
    expect((await POST(request({ ...confirmation, action: "remove" }))).status).toBe(409); expect(mocks.write).toHaveBeenCalledOnce();
  });

  it("supports null legacy numeric IDs and equivalent timestamp serialization without guessing", async () => {
    mocks.repositories.mockResolvedValue({ data: [{ ...repository, github_repo_id: null }], error: null });
    mocks.write.mockResolvedValue({ data: { ...stored, github_repo_id: null, confirmed_at: "2026-09-17T10:00:00+00:00" }, error: null });
    expect((await POST(request({ ...confirmation, expectedGithubRepositoryId: null }))).status).toBe(200);
  });

  it("never acknowledges a failed post-write context read", async () => {
    mocks.profile.mockResolvedValueOnce({ data: profile, error: null }).mockResolvedValue({ data: null, error: { message: "private-error" } });
    expect((await POST(request(confirmation))).status).toBe(503); expect(mocks.write).toHaveBeenCalledOnce();
  });

  it("requires explicit approval and rejects client authority/transport-shape changes", async () => {
    for (const change of [{ confirmed: false }, { userId: "other" }, { collector: "postgres-direct" },
      { expectedEndpointUrl: endpoint === null ? url : null }, { expectedProjectRef: "<script>" }]) {
      expect((await POST(request({ ...confirmation, ...change }))).status).toBe(400);
    }
    expect(mocks.write).not.toHaveBeenCalled();
  });
});

describe("Supabase repository route security", () => {
  it.each(["", "?collector=postgres-direct", "?collector=supabase-scan&collector=supabase-management", "?collector=supabase-management&userId=other"])(
    "requires one explicit supported transport selector: %s", async (query) => {
      expect((await GET(new Request(`https://shiplock.dev/api/deep/supabase/repository${query}`))).status).toBe(400);
      expect(mocks.profile).not.toHaveBeenCalled();
    });

  it("requires the existing session gate before any storage read/write", async () => {
    mocks.gate.mockResolvedValue(null);
    expect((await get("supabase-management")).status).toBe(403); expect((await POST(request({}))).status).toBe(403);
    expect(mocks.profile).not.toHaveBeenCalled(); expect(mocks.write).not.toHaveBeenCalled();
  });

  it.each([null, "null", "https://evil.example"])("refuses missing/cross-site Origin: %s", async (origin) => {
    const req = request({}); if (origin === null) req.headers.delete("Origin"); else req.headers.set("Origin", origin);
    expect((await POST(req)).status).toBe(403); expect(mocks.profile).not.toHaveBeenCalled();
  });

  it("requires JSON and cancels oversized streamed bodies, irrespective of Content-Length", async () => {
    expect((await POST(request({}, { "Content-Type": "text/plain" }))).status).toBe(415);
    const cancel = vi.fn(); const init = { method: "POST", headers: { Origin: "https://shiplock.dev", "Content-Type": "application/json", "Content-Length": "1" },
      body: new ReadableStream({ start(controller) { controller.enqueue(new TextEncoder().encode("x".repeat(8193))); }, cancel }), duplex: "half" };
    expect((await POST(new Request("https://shiplock.dev/api/deep/supabase/repository", init))).status).toBe(400);
    expect(cancel).toHaveBeenCalledOnce(); expect(mocks.profile).not.toHaveBeenCalled();
  });

  it.each(["{", new Uint8Array([0xff]), null])("rejects malformed JSON, invalid UTF-8 and missing body: %j", async (body) => {
    const req = new Request("https://shiplock.dev/api/deep/supabase/repository", { method: "POST",
      headers: { Origin: "https://shiplock.dev", "Content-Type": "application/json" }, body });
    expect((await POST(req)).status).toBe(400); expect(mocks.profile).not.toHaveBeenCalled(); expect(mocks.write).not.toHaveBeenCalled();
  });

  it("contains thrown storage errors without leaking credentials into responses or logs", async () => {
    const log = vi.spyOn(console, "error").mockImplementation(() => {});
    mocks.profile.mockRejectedValue(new Error("shared-encrypted private-error"));
    const response = await get("supabase-scan"); expect(response.status).toBe(503);
    expect(await response.text()).not.toContain("shared-encrypted"); expect(JSON.stringify(log.mock.calls)).not.toContain("shared-encrypted");
  });
});
