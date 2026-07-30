import { describe, expect, it } from "vitest";
import {
  AUTH_HOOK_SQL,
  checkAuthHooks,
  checkRealtimeTables,
  REALTIME_SQL,
  scanRealtimeAndHooks,
} from "./realtimeScan";
import { assertReadOnly } from "./supabaseMgmt";

const table = (over: Partial<Parameters<typeof checkRealtimeTables>[0][0]> = {}) => ({
  schema: "public", name: "messages", rls_enabled: true, policy_count: 1, ...over,
});
const hook = (over: Partial<Parameters<typeof checkAuthHooks>[0][0]> = {}) => ({
  schema: "public", name: "custom_access_token_hook", security_definer: true, config: "", ...over,
});

describe("A14 — Realtime authorisation", () => {
  // Our own project publishes nothing, which must be silent.
  it("is silent when nothing is published", () => {
    expect(checkRealtimeTables([])).toEqual([]);
  });

  it("is silent on a published table with RLS and a policy", () => {
    expect(checkRealtimeTables([table()])).toEqual([]);
  });

  it("flags a published table with RLS off", () => {
    const out = checkRealtimeTables([table({ rls_enabled: false })]);
    expect(out).toHaveLength(1);
    expect(out[0].severity).toBe("CRITICAL");
  });

  // Why this is worse than an open SELECT, and why it gets missed.
  it("explains that it is a continuous feed leaving no request in the logs", () => {
    const out = checkRealtimeTables([table({ rls_enabled: false })]);
    expect(out[0].consequence).toContain("continuous feed");
    expect(out[0].consequence).toContain("no request in the logs");
  });

  it("says Realtime is configured somewhere else than the API surface", () => {
    const out = checkRealtimeTables([table({ rls_enabled: false })]);
    expect(out[0].consequence).toContain("configured somewhere else");
  });

  it("groups several exposed tables into one finding", () => {
    const out = checkRealtimeTables([
      table({ name: "messages", rls_enabled: false }),
      table({ name: "orders", rls_enabled: false }),
    ]);
    expect(out).toHaveLength(1);
    expect(out[0].title).toContain("public.messages, public.orders");
  });

  // Safe, but usually not what was intended.
  it("notes a published table that delivers nothing, at INFO", () => {
    const out = checkRealtimeTables([table({ policy_count: 0 })]);
    expect(out[0].severity).toBe("INFO");
    expect(out[0].consequence).toContain("nothing is leaking");
  });

  it("can report both states at once", () => {
    const out = checkRealtimeTables([
      table({ name: "a", rls_enabled: false }),
      table({ name: "b", policy_count: 0 }),
    ]);
    expect(out).toHaveLength(2);
  });
});

describe("A20 — auth hooks", () => {
  it("is silent when there are no hooks", () => {
    expect(checkAuthHooks([])).toEqual([]);
  });

  it("is silent on a hook with a pinned search_path", () => {
    expect(checkAuthHooks([hook({ config: "search_path=" })])).toEqual([]);
  });

  it("is silent on a non-definer hook", () => {
    expect(checkAuthHooks([hook({ security_definer: false })])).toEqual([]);
  });

  it("flags a definer hook with a mutable search_path", () => {
    const out = checkAuthHooks([hook()]);
    expect(out).toHaveLength(1);
    expect(out[0].severity).toBe("WARNING");
  });

  // Why a hook matters more than an ordinary function with the same flaw.
  it("connects it to the claims policies trust", () => {
    const out = checkAuthHooks([hook()]);
    expect(out[0].consequence).toContain("signed access token");
    expect(out[0].consequence).toContain("admins can read everything");
  });
});

describe("scanRealtimeAndHooks", () => {
  it("checks nothing it was not given", () => {
    expect(scanRealtimeAndHooks({})).toEqual([]);
  });

  it("is silent on our own project's shape", () => {
    expect(scanRealtimeAndHooks({ realtimeTables: [], authHooks: [] })).toEqual([]);
  });

  it("combines both", () => {
    const out = scanRealtimeAndHooks({
      realtimeTables: [table({ rls_enabled: false })],
      authHooks: [hook()],
    });
    expect(out).toHaveLength(2);
    expect(new Set(out.map((x) => x.id)).size).toBe(2);
  });
});

describe("the queries", () => {
  it("pass the read-only guard", () => {
    expect(() => assertReadOnly(REALTIME_SQL)).not.toThrow();
    expect(() => assertReadOnly(AUTH_HOOK_SQL)).not.toThrow();
  });

  it("scope Realtime to the supabase_realtime publication", () => {
    expect(REALTIME_SQL).toContain("supabase_realtime");
  });
});
