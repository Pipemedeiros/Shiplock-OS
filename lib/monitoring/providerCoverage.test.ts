import { describe, expect, it } from "vitest";
import { summarizeProviderCoverage, type ProviderConnection, type SnapshotRow } from "./providerCoverage";

// 5A-3: Coverage says, per provider, what the latest read covered. A
// disconnected or reconnected provider never shows an older read as current.
const epoch = "a".repeat(64);
const connectedAt = "2026-09-20T10:00:00.000Z";
const mgmt = (over: Partial<ProviderConnection> = {}): ProviderConnection =>
  ({ transport: "supabase-management", connected: true, identity: epoch, connectedAt, ...over });
const row = (over: Partial<SnapshotRow> = {}): SnapshotRow => ({
  transport: "supabase-management", connection_identity: epoch, observed_at: "2026-09-22T10:00:00.000Z",
  completeness: "complete", unread: [], reason: null, finding_count: 3, scope: "proj", ...over,
});
const only = (connections: ProviderConnection[], rows: SnapshotRow[]) => summarizeProviderCoverage(connections, rows)[0];

describe("summarizeProviderCoverage", () => {
  it("does not list a provider that is not connected, even with old reads", () => {
    expect(summarizeProviderCoverage([mgmt({ connected: false, identity: null })], [row()])).toEqual([]);
  });

  it("says a connected provider has not been read yet", () => {
    expect(only([mgmt()], [])).toMatchObject({ label: "Supabase project", state: "never_read", observedAt: null });
  });

  it("reports a complete read with its time", () => {
    expect(only([mgmt()], [row()])).toMatchObject({ state: "complete", observedAt: "2026-09-22T10:00:00.000Z", notRead: [] });
  });

  it("names what a partial read could not read, in plain words, once each", () => {
    const item = only([mgmt()], [row({ completeness: "partial", unread: ["advisor:", "auth_redirect:", "auth_site_url:", "auth_policy:", "grants:"] })]);
    expect(item.state).toBe("partial");
    expect(item.notRead).toEqual(["Supabase security advisors", "Auth settings", "Column grants"]);
  });

  it("names an unreadable Vercel project", () => {
    const item = only([{ transport: "vercel", connected: true, identity: epoch, connectedAt }],
      [row({ transport: "vercel", completeness: "partial", unread: ["vercel:marketing-site:"] })]);
    expect(item.notRead).toEqual(["Vercel project marketing-site"]);
  });

  it("explains a failed read by its reason code", () => {
    const item = only([mgmt()], [row({ completeness: "failed", reason: "auth_failed", connection_identity: null, finding_count: null })]);
    expect(item).toMatchObject({ state: "failed" });
    expect(item.detail).toMatch(/refused/i);
  });

  it("does not show a read from before a reconnect as current", () => {
    expect(only([mgmt({ identity: "b".repeat(64) })], [row()]).state).toBe("stale_connection");
    const failedBefore = row({ completeness: "failed", reason: "timeout", connection_identity: null, observed_at: "2026-09-19T10:00:00.000Z" });
    expect(only([mgmt()], [failedBefore]).state).toBe("stale_connection");
  });

  it("uses the newest row per transport", () => {
    const item = only([mgmt()], [row({ observed_at: "2026-09-21T10:00:00.000Z", completeness: "failed", reason: "timeout", connection_identity: null }), row()]);
    expect(item.state).toBe("complete");
  });

  it("keeps every customer-facing string free of dashes", () => {
    const states = [only([mgmt()], []), only([mgmt()], [row({ completeness: "failed", reason: "timeout", connection_identity: null })]),
      only([mgmt({ identity: "b".repeat(64) })], [row()])];
    for (const item of states) expect(`${item.label} ${item.detail}`).not.toMatch(/[–—]| - /);
  });
});

describe("getProviderCoverage", () => {
  it("reads only the caller's rows and fails soft", async () => {
    const { vi } = await import("vitest");
    const filters: unknown[][] = [];
    const result = (data: unknown, error: unknown = null) => ({ data, error });
    vi.resetModules();
    vi.doMock("@/lib/supabase", () => ({ getSupabaseAdmin: () => ({ from: (table: string) => {
      const q = {
        select: () => q, order: () => q,
        eq: (...args: unknown[]) => { filters.push([table, ...args]); return q; },
        maybeSingle: async () => result({ supabase_mgmt_token_encrypted: "c", supabase_mgmt_connection_epoch: epoch, supabase_mgmt_connected_at: connectedAt }),
        limit: async () => table === "provider_snapshots" ? result(null, { message: "down" }) : result([]),
      };
      return q;
    } }) }));
    const { getProviderCoverage } = await import("./providerCoverage");
    expect(await getProviderCoverage("user-1")).toEqual({ available: false, items: [] });
    expect(filters).toEqual([["user_profiles", "id", "user-1"], ["provider_snapshots", "user_id", "user-1"]]);
    vi.doUnmock("@/lib/supabase");
  });
});
