import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createDirectRepositoryConfirmation } from "./directRepositoryConfirmation";

const id = "22222222-2222-4222-8222-222222222222";
const context = { available: true, databaseDisplay: "shiplock_reader@db.example:5432/app", connectionFingerprint: "a".repeat(64), installationId: "42",
  githubConnectedAt: "2026-09-17T09:00:00.000Z", repositories: [{ id, fullName: "acme/app", githubRepoId: "7" }], bindings: [] };
const binding = { repositoryId: id, method: "customer_confirmed", confirmedAt: "2026-09-17T10:00:00.000Z" };
const reply = (value: unknown, status = 200) => Promise.resolve(Response.json(value, { status }));
const transport = vi.fn<typeof fetch>();
const controller = () => createDirectRepositoryConfirmation(transport);

beforeEach(() => {
  vi.spyOn(Date, "now").mockReturnValue(Date.parse("2026-09-17T11:00:00.000Z"));
  transport.mockReset().mockImplementation(() => reply(context));
});
afterEach(() => vi.restoreAllMocks());

describe("explicit Settings confirmation state", () => {
  it("loads current context without performing a write", async () => {
    const model = controller(); await model.load();
    expect(model.getSnapshot()).toMatchObject({ status: "ready", context });
    expect(transport).toHaveBeenCalledWith("/api/deep/postgres/repository", expect.objectContaining({ method: "GET", cache: "no-store", credentials: "same-origin" }));
    expect(transport).toHaveBeenCalledTimes(1);
  });

  it("requires review then approval; review/cancel alone never POST", async () => {
    const model = controller(); await model.load();
    await model.approve(); expect(transport).toHaveBeenCalledTimes(1);
    model.review(id, "confirm"); expect(model.getSnapshot().status).toBe("review");
    model.cancel(); expect(model.getSnapshot().status).toBe("ready");
    expect(transport).toHaveBeenCalledTimes(1);
  });

  it("sends exactly displayed context and verifies saved state by rereading", async () => {
    const model = controller(); await model.load(); model.review(id, "confirm");
    transport.mockImplementationOnce(() => reply({ ok: true, method: "customer_confirmed" }))
      .mockImplementationOnce(() => reply({ ...context, bindings: [binding] }));
    await model.approve();
    const init = transport.mock.calls[1][1];
    expect(JSON.parse(init?.body as string)).toEqual({ action: "confirm", confirmed: true, repositoryId: id,
      expectedConnectionFingerprint: context.connectionFingerprint, expectedInstallationId: "42", expectedGithubConnectedAt: context.githubConnectedAt,
      expectedRepositoryFullName: "acme/app", expectedGithubRepositoryId: "7" });
    expect(model.getSnapshot()).toMatchObject({ status: "ready", context: { bindings: [binding] }, message: "Association confirmed by you." });
    expect(transport.mock.calls[2][1]?.method).toBe("GET");
  });

  it("also requires review/approval for removal and rereads the absence", async () => {
    transport.mockImplementationOnce(() => reply({ ...context, bindings: [binding] }));
    const model = controller(); await model.load(); model.review(id, "remove");
    expect(transport).toHaveBeenCalledTimes(1);
    transport.mockImplementationOnce(() => reply({ ok: true, method: "customer_confirmed" })).mockImplementationOnce(() => reply(context));
    await model.approve();
    expect(JSON.parse(transport.mock.calls[1][1]?.body as string).action).toBe("remove");
    expect(model.getSnapshot()).toMatchObject({ status: "ready", context: { bindings: [] }, message: "Association removed." });
  });

  it.each(["confirm", "remove"] as const)("refuses an unselected repository for %s", async (action) => {
    const model = controller(); await model.load(); model.review("other", action); await model.approve();
    expect(transport).toHaveBeenCalledTimes(1);
  });

  it("does not offer removal for an unconfirmed repository", async () => {
    const model = controller(); await model.load(); model.review(id, "remove"); await model.approve();
    expect(transport).toHaveBeenCalledTimes(1);
  });

  it.each([403, 503])("keeps load failure %s unknown, not confirmed or clean", async (status) => {
    transport.mockImplementationOnce(() => reply({ error: "private-error" }, status));
    const model = controller(); await model.load();
    expect(model.getSnapshot().status).toBe("unavailable"); expect(model.getSnapshot().context).toBeUndefined();
    model.review(id, "confirm"); await model.approve(); expect(transport).toHaveBeenCalledTimes(1);
    expect(JSON.stringify(model.getSnapshot())).not.toContain("private-error");
  });

  it.each([{ available: false, repositories: [], bindings: [] }, { ...context, repositories: [] }])(
    "distinguishes missing connection context from no selected repositories: %j", async (value) => {
      transport.mockImplementationOnce(() => reply(value)); const model = controller(); await model.load();
      expect(model.getSnapshot().status).toBe(value.available ? "ready" : "unconfigured");
    });

  it.each([{ ...context, connectionFingerprint: "invalid" }, { ...context, bindings: [{ ...binding, method: "proven" }] },
    { ...context, repositories: [context.repositories[0], context.repositories[0]] }, { ...context, bindings: [{ ...binding, repositoryId: "other" }] },
    { ...context, bindings: [binding, binding] }, { ...context, repositories: [{ ...context.repositories[0], githubRepoId: 7 }] }])(
    "rejects malformed or contradictory context: %j", async (value) => {
      transport.mockImplementationOnce(() => reply(value)); const model = controller(); await model.load();
      expect(model.getSnapshot().status).toBe("unavailable"); expect(model.getSnapshot().context).toBeUndefined();
    });

  it("does not treat a successful write acknowledgement as a saved confirmation", async () => {
    const model = controller(); await model.load(); model.review(id, "confirm");
    transport.mockImplementationOnce(() => reply({ ok: true, method: "customer_confirmed" })).mockImplementationOnce(() => reply(context));
    await model.approve(); expect(model.getSnapshot().status).toBe("unavailable");
    expect(model.getSnapshot().context).toBeUndefined();
  });

  it("refuses false success when removal still appears in the reread", async () => {
    transport.mockImplementationOnce(() => reply({ ...context, bindings: [binding] }));
    const model = controller(); await model.load(); model.review(id, "remove");
    transport.mockImplementationOnce(() => reply({ ok: true, method: "customer_confirmed" }))
      .mockImplementationOnce(() => reply({ ...context, bindings: [binding] }));
    await model.approve(); expect(model.getSnapshot().status).toBe("unavailable");
  });

  it("requires a fresh review after a 409, with no automatic retry or POST on reload", async () => {
    const model = controller(); await model.load(); model.review(id, "confirm");
    transport.mockImplementationOnce(() => reply({ error: "stale" }, 409)); await model.approve();
    expect(model.getSnapshot().status).toBe("stale"); expect(model.getSnapshot().context).toBeUndefined();
    await model.approve(); expect(transport).toHaveBeenCalledTimes(2);
    await model.load(); await model.approve(); expect(transport).toHaveBeenCalledTimes(3);
  });

  it.each(["write-error", "network-error", "malformed-ack", "reread-error", "changed-context"])(
    "never claims saved state across %s", async (kind) => {
      const model = controller(); await model.load(); model.review(id, "confirm");
      if (kind === "network-error") transport.mockRejectedValueOnce(new Error("private-error"));
      else transport.mockImplementationOnce(() => reply(kind === "malformed-ack" ? { ok: true } : { ok: true, method: "customer_confirmed" }, kind === "write-error" ? 503 : 200));
      transport.mockImplementationOnce(() => reply(kind === "changed-context" ? { ...context, connectionFingerprint: "b".repeat(64), bindings: [binding] } : { error: "private-error" }, kind === "reread-error" ? 503 : 200));
      await model.approve();
      expect(model.getSnapshot().status).toBe(kind === "changed-context" ? "stale" : "unavailable");
      expect(model.getSnapshot().context).toBeUndefined();
    });

  it("discards delayed loads after suspension and cannot approve while saving", async () => {
    let resolve!: (response: Response) => void;
    transport.mockImplementationOnce(() => new Promise((done) => { resolve = done; }));
    const model = controller(); const pending = model.load(); model.suspend();
    resolve(Response.json(context)); await pending; expect(model.getSnapshot().context).toBeUndefined();
    await model.load(); model.review(id, "confirm");
    transport.mockImplementationOnce(() => new Promise((done) => { resolve = done; }));
    const saving = model.approve(); expect(model.getSnapshot().status).toBe("saving");
    await model.approve(); model.review(id, "confirm"); model.cancel();
    expect(model.getSnapshot().status).toBe("saving"); expect(transport).toHaveBeenCalledTimes(3);
    model.suspend(); resolve(Response.json({ ok: true, method: "customer_confirmed" })); await saving;
    expect(transport).toHaveBeenCalledTimes(3); expect(model.getSnapshot().context).toBeUndefined();
  });

  it.each([{ ...context, databaseDisplay: null }, { ...context, databaseDisplay: "" },
    { ...context, githubConnectedAt: "2026-09-18T00:00:00Z" },
    { ...context, bindings: [{ ...binding, confirmedAt: "2026-09-18T00:00:00Z" }] },
    { ...context, bindings: [{ ...binding, confirmedAt: "2026-09-16T00:00:00Z" }] },
    { ...context, repositories: [...context.repositories, { ...context.repositories[0], id: "33333333-3333-4333-8333-333333333333", fullName: "acme/other" }] }])(
    "excludes unavailable labels, inconsistent dates and duplicated numeric identity: %j", async (value) => {
      transport.mockImplementationOnce(() => reply(value)); const model = controller(); await model.load();
      expect(model.getSnapshot().status).toBe("unavailable"); expect(model.getSnapshot().context).toBeUndefined();
    });

  it("uses the freshly fetched database label and refuses changed labels after writing", async () => {
    transport.mockImplementationOnce(() => reply({ ...context, databaseDisplay: "current.example/app" }));
    const model = controller(); await model.load(); model.review(id, "confirm");
    expect(model.getSnapshot().context?.databaseDisplay).toBe("current.example/app");
    transport.mockImplementationOnce(() => reply({ ok: true, method: "customer_confirmed" }))
      .mockImplementationOnce(() => reply({ ...context, bindings: [binding] }));
    await model.approve(); expect(model.getSnapshot().status).toBe("stale");
    expect(model.getSnapshot().context).toBeUndefined();
  });

  it("strips unknown fields rather than keeping private server context in state", async () => {
    transport.mockImplementationOnce(() => reply({ ...context, postgres_dsn_encrypted: "private-value",
      repositories: [{ ...context.repositories[0], private: "private-value" }] }));
    const model = controller(); await model.load();
    expect(model.getSnapshot().status).toBe("ready"); expect(JSON.stringify(model.getSnapshot())).not.toContain("private-value");
  });

  it("a newer load wins even if an aborted older request finishes later", async () => {
    let resolve!: (response: Response) => void;
    transport.mockImplementationOnce(() => new Promise((done) => { resolve = done; }));
    const model = controller(); const old = model.load(); await model.load();
    resolve(Response.json({ ...context, databaseDisplay: "old.example/app", bindings: [binding] })); await old;
    expect(model.getSnapshot()).toMatchObject({ status: "ready", context });
    expect(transport.mock.calls[0][1]?.signal?.aborted).toBe(true);
  });

  it("unsubscribes listeners and can restart after a Strict Mode style cleanup", async () => {
    const model = controller(); const listener = vi.fn(); const unsubscribe = model.subscribe(listener);
    await model.load(); unsubscribe(); listener.mockClear(); model.suspend(); await model.load();
    expect(listener).not.toHaveBeenCalled(); expect(model.getSnapshot().status).toBe("ready");
    expect(model.getServerSnapshot()).toEqual({ status: "loading" });
  });
});
