import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createSupabaseRepositoryConfirmation, type SupabaseBindingCollector } from "./supabaseRepositoryConfirmation";

const id = "22222222-2222-4222-8222-222222222222", connectedAt = "2026-09-17T09:00:00.000Z";
const binding = { repositoryId: id, method: "customer_confirmed" as const, confirmedAt: "2026-09-17T10:00:00.000Z" };
const cases = [
  { collector: "supabase-management", endpointUrl: null },
  { collector: "supabase-scan", endpointUrl: "https://project-a.supabase.co" },
] as const;
const context = (collector: SupabaseBindingCollector, endpointUrl: string | null, bindings: typeof binding[] = []) => ({
  available: true as const, collector, projectRef: "project-a", endpointUrl, connectionFingerprint: "a".repeat(64), installationId: "42",
  githubConnectedAt: connectedAt, repositories: [{ id, fullName: "acme/app", githubRepoId: "7" }], bindings,
});
const reply = (value: unknown, status = 200) => Promise.resolve(Response.json(value, { status }));

describe.each(cases)("$collector client confirmation", ({ collector, endpointUrl }) => {
  const current = context(collector, endpointUrl); const transport = vi.fn<typeof fetch>();
  beforeEach(() => {
    vi.spyOn(Date, "now").mockReturnValue(Date.parse("2026-09-17T11:00:00Z"));
    transport.mockReset().mockImplementation(() => reply(current));
  });
  afterEach(() => vi.restoreAllMocks());

  it("loads only its explicit no-store transport context", async () => {
    const model = createSupabaseRepositoryConfirmation(collector, transport); await model.load();
    expect(model.getSnapshot()).toMatchObject({ status: "ready", context: current });
    expect(transport).toHaveBeenCalledWith(`/api/deep/supabase/repository?collector=${collector}`,
      expect.objectContaining({ method: "GET", cache: "no-store", credentials: "same-origin" }));
  });

  it("distinguishes an unconfigured path from a failed context read", async () => {
    const model = createSupabaseRepositoryConfirmation(collector, transport);
    transport.mockImplementationOnce(() => reply({ available: false, collector, repositories: [], bindings: [], privateCredential: "secret" }));
    await model.load(); expect(model.getSnapshot()).toEqual({ status: "unconfigured" });
    transport.mockImplementationOnce(() => reply({ error: "private-error" }, 503));
    await model.load(); expect(model.getSnapshot().status).toBe("unavailable");
    expect(JSON.stringify(model.getSnapshot())).not.toMatch(/private-error|secret/);
  });

  it.each(["confirm", "remove"] as const)("refuses an invalid %s review without writing", async (action) => {
    const model = createSupabaseRepositoryConfirmation(collector, transport); await model.load();
    model.review(action === "confirm" ? "other" : id, action); await model.approve();
    expect(model.getSnapshot().status).toBe("ready"); expect(transport).toHaveBeenCalledOnce();
  });

  it("requires review before POST and rereads corroborating state", async () => {
    const model = createSupabaseRepositoryConfirmation(collector, transport); await model.load();
    await model.approve(); model.review(id, "confirm"); expect(transport).toHaveBeenCalledOnce();
    transport.mockImplementationOnce(() => reply({ ok: true, collector, method: "customer_confirmed" }))
      .mockImplementationOnce(() => reply(context(collector, endpointUrl, [binding])));
    await model.approve();
    expect(JSON.parse(transport.mock.calls[1][1]?.body as string)).toEqual({ action: "confirm", confirmed: true, collector, repositoryId: id,
      expectedProjectRef: "project-a", expectedEndpointUrl: endpointUrl, expectedConnectionFingerprint: "a".repeat(64),
      expectedInstallationId: "42", expectedGithubConnectedAt: connectedAt, expectedRepositoryFullName: "acme/app", expectedGithubRepositoryId: "7" });
    expect(model.getSnapshot()).toMatchObject({ status: "ready", context: { bindings: [binding] }, message: "Association confirmed by you." });
  });

  it("requires separate review for removal and verifies absence", async () => {
    transport.mockImplementationOnce(() => reply(context(collector, endpointUrl, [binding])));
    const model = createSupabaseRepositoryConfirmation(collector, transport); await model.load(); model.review(id, "remove"); model.cancel();
    expect(transport).toHaveBeenCalledOnce(); model.review(id, "remove");
    transport.mockImplementationOnce(() => reply({ ok: true, collector, method: "customer_confirmed" })).mockImplementationOnce(() => reply(current));
    await model.approve(); expect(model.getSnapshot()).toMatchObject({ status: "ready", context: { bindings: [] }, message: "Association removed." });
  });

  it.each(["wrong-ack", "write-error", "missing-confirmation", "changed-project", "changed-endpoint", "changed-collector",
    "changed-fingerprint", "changed-installation", "changed-github-connection", "changed-repository-name", "changed-github-repository"])(
    "never claims saved state after %s", async (kind) => {
      const model = createSupabaseRepositoryConfirmation(collector, transport); await model.load(); model.review(id, "confirm");
      transport.mockImplementationOnce(() => reply(kind === "wrong-ack" ? { ok: true, collector: collector === "supabase-scan" ? "supabase-management" : "supabase-scan", method: "customer_confirmed" }
        : { ok: true, collector, method: "customer_confirmed" }, kind === "write-error" ? 503 : 200));
      transport.mockImplementationOnce(() => reply(kind === "missing-confirmation" ? current : kind === "changed-project" ? { ...current, projectRef: "project-b",
        endpointUrl: collector === "supabase-scan" ? "https://project-b.supabase.co" : null, bindings: [binding] }
        : kind === "changed-endpoint" ? { ...current, endpointUrl: endpointUrl ? "https://project-b.supabase.co" : "https://project-a.supabase.co", bindings: [binding] }
          : kind === "changed-collector" ? { ...current, collector: collector === "supabase-scan" ? "supabase-management" : "supabase-scan", bindings: [binding] }
            : kind === "changed-fingerprint" ? { ...current, connectionFingerprint: "b".repeat(64), bindings: [binding] }
              : kind === "changed-installation" ? { ...current, installationId: "43", bindings: [binding] }
                : kind === "changed-github-connection" ? { ...current, githubConnectedAt: "2026-09-17T09:30:00.000Z", bindings: [binding] }
                  : kind === "changed-repository-name" ? { ...current, repositories: [{ ...current.repositories[0], fullName: "acme/other" }], bindings: [binding] }
                    : { ...current, repositories: [{ ...current.repositories[0], githubRepoId: "8" }], bindings: [binding] }));
      await model.approve();
      expect(model.getSnapshot().status).toBe(["changed-project", "changed-fingerprint", "changed-installation", "changed-github-connection",
        "changed-repository-name", "changed-github-repository"].includes(kind) ? "stale" : "unavailable");
      expect(model.getSnapshot().context).toBeUndefined();
    });

  it.each([{ ...current, collector: "postgres-direct" }, { ...current, projectRef: "<script>" },
    { ...current, endpointUrl: collector === "supabase-scan" ? null : "https://project-a.supabase.co" },
    { ...current, githubConnectedAt: "2026-09-20T00:00:00Z" }, { ...current, bindings: [{ ...binding, confirmedAt: "2026-09-16T00:00:00Z" }] },
    { ...current, repositories: [current.repositories[0], current.repositories[0]] }, { ...current, privateCredential: "secret" }])(
    "fails closed or strips non-protocol context: %j", async (value) => {
      transport.mockImplementationOnce(() => reply(value)); const model = createSupabaseRepositoryConfirmation(collector, transport); await model.load();
      if ("privateCredential" in value) { expect(model.getSnapshot().status).toBe("ready"); expect(JSON.stringify(model.getSnapshot())).not.toContain("secret"); }
      else { expect(model.getSnapshot().status).toBe("unavailable"); expect(model.getSnapshot().context).toBeUndefined(); }
    });

  it("invalidates delayed responses and requires fresh review after 409", async () => {
    let resolve!: (response: Response) => void;
    transport.mockImplementationOnce(() => new Promise((done) => { resolve = done; }));
    const model = createSupabaseRepositoryConfirmation(collector, transport); const pending = model.load(); model.suspend();
    resolve(Response.json(current)); await pending; expect(model.getSnapshot().context).toBeUndefined();
    await model.load(); model.review(id, "confirm"); transport.mockImplementationOnce(() => reply({}, 409)); await model.approve();
    expect(model.getSnapshot().status).toBe("stale"); expect(model.getSnapshot().context).toBeUndefined();
    await model.approve(); expect(transport).toHaveBeenCalledTimes(3);
  });

  it("does not permit another action while a save is unresolved", async () => {
    let resolve!: (response: Response) => void;
    const model = createSupabaseRepositoryConfirmation(collector, transport); await model.load(); model.review(id, "confirm");
    transport.mockImplementationOnce(() => new Promise((done) => { resolve = done; }));
    const saving = model.approve(); expect(model.getSnapshot().status).toBe("saving");
    await model.approve(); model.review(id, "confirm"); model.cancel(); expect(transport).toHaveBeenCalledTimes(2);
    model.suspend(); resolve(Response.json({ ok: true, collector, method: "customer_confirmed" })); await saving;
    expect(model.getSnapshot()).toEqual({ status: "loading" }); expect(transport).toHaveBeenCalledTimes(2);
  });
});

it("does not share state or writes across Supabase transports", async () => {
  const transport = vi.fn<typeof fetch>().mockImplementation((input) => reply(context(String(input).includes("scan") ? "supabase-scan" : "supabase-management",
    String(input).includes("scan") ? "https://project-a.supabase.co" : null)));
  const management = createSupabaseRepositoryConfirmation("supabase-management", transport);
  const endpoint = createSupabaseRepositoryConfirmation("supabase-scan", transport);
  await management.load(); await endpoint.load(); management.review(id, "confirm");
  expect(management.getSnapshot().status).toBe("review"); expect(endpoint.getSnapshot().status).toBe("ready"); expect(transport).toHaveBeenCalledTimes(2);
});
