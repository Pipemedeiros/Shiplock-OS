import { describe, expect, it } from "vitest";
import { DEFAULT_COLLECTORS, directPostgresCollector, supabaseManagementCollector, vercelEnvCollector } from "./collectors";
import type { CollectorContext } from "./registry";
import type { MonitoredProfile } from "./types";

// This file exists because of a bug class, not a feature.
//
// This repository has had collectors written without being registered,
// tested, and never reached a customer because nothing called it. The code was
// fine every time; the wiring was missing, and unit tests of the collector
// itself could not have caught it. So the registration is asserted directly.
//
// If you are deleting a case here, check you are not also deleting the only
// thing that would notice a collector silently leaving the schedule.

const profile = (over: Partial<MonitoredProfile> = {}): MonitoredProfile => ({
  id: "user-1",
  email: "founder@example.com",
  monitored_project_url: "https://abc.supabase.co",
  monitored_anon_key_encrypted: "enc",
  ...over,
});

const ctx = (p: MonitoredProfile): CollectorContext => ({
  profile: p,
  anonKey: "anon",
  triggerSource: "scheduled_48h",
  previousFindings: [],
});

describe("collector registration", () => {
  it("includes the direct-Postgres collector in the default registry", () => {
    // The whole point of the widening: a Neon or RDS customer's database is read
    // on the same schedule as a Supabase customer's, with no separate trigger.
    expect(DEFAULT_COLLECTORS).toContain(directPostgresCollector);
  });

  it("includes Supabase Management only when its read-only connection exists",()=>{
    expect(DEFAULT_COLLECTORS).toContain(supabaseManagementCollector);
    expect(supabaseManagementCollector.appliesTo?.(ctx(profile({
      supabase_mgmt_token_encrypted:"enc",supabase_mgmt_project_ref:"project-ref",
    })))).toBe(true);
    expect(supabaseManagementCollector.appliesTo?.(ctx(profile({supabase_mgmt_token_encrypted:"enc"})))).toBe(false);
    expect(supabaseManagementCollector.appliesTo?.(ctx(profile()))).toBe(false);
  });

  it("gives every collector a unique id", () => {
    const ids = DEFAULT_COLLECTORS.map((c) => c.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("gives every collector a timeout, so none can consume the whole pass", () => {
    for (const c of DEFAULT_COLLECTORS) {
      expect(c.timeoutMs, c.id).toBeGreaterThan(0);
      expect(c.eligibleTriggers.length, c.id).toBeGreaterThan(0);
    }
  });
});

describe("direct-Postgres collector gating", () => {
  it("applies only when a connection string is stored", () => {
    expect(directPostgresCollector.appliesTo?.(ctx(profile({ postgres_dsn_encrypted: "enc" })))).toBe(
      true
    );
  });

  it("does not apply to a Supabase-connected customer", () => {
    // Not a failure — "not applicable". The two fill the same slot, so a
    // customer has one or the other and the unused one must stay silent rather
    // than reporting an error every pass.
    expect(directPostgresCollector.appliesTo?.(ctx(profile()))).toBe(false);
  });

  it("does not run on the hourly pass", () => {
    // Opening a TCP session to a customer's primary database every hour is a
    // different cost profile from the hourly HTTP subset, and policy text does
    // not change hourly.
    expect(directPostgresCollector.eligibleTriggers).not.toContain("hourly");
    expect(directPostgresCollector.eligibleTriggers).toContain("scheduled_48h");
  });

  it("reports the db layer, so it lands in the same slot as the Supabase scan", () => {
    expect(directPostgresCollector.layer).toBe("db");
  });
});

describe("the Vercel environment audit is on the schedule", () => {
  // lib/deep/vercel.ts and vercelRun.ts were written, tested, and reachable
  // only from a settings button no page rendered. That is the fifth recorded
  // instance in this repository of a collector that existed and was never
  // called, which is what this file exists to stop.
  it("is registered", () => {
    expect(DEFAULT_COLLECTORS).toContain(vercelEnvCollector);
  });

  it("only runs for an account that connected Vercel", () => {
    const profile = (over: Record<string, unknown>) =>
      ({
        profile: {
          id: "u", email: null, monitored_project_url: "https://x.supabase.co",
          monitored_anon_key_encrypted: "enc", ...over,
        },
      }) as never;

    expect(vercelEnvCollector.appliesTo?.(profile({ vercel_access_token_encrypted: "enc", vercel_connection_epoch: "e".repeat(64) }))).toBe(true);
    // A token without a connection epoch is not a usable connection.
    expect(vercelEnvCollector.appliesTo?.(profile({ vercel_access_token_encrypted: "enc" }))).toBe(false);
    expect(vercelEnvCollector.appliesTo?.(profile({}))).toBe(false);
  });

  it("stays off the hourly pass", () => {
    // Environment variables change on deploy, not minute to minute, and the
    // hourly pass is the one with a wall-clock budget.
    expect(vercelEnvCollector.eligibleTriggers).not.toContain("hourly");
    expect(vercelEnvCollector.eligibleTriggers).toContain("scheduled_48h");
  });

describe("customer rechecks run every full-pass collector", () => {
  it("makes each deploy-eligible collector eligible for manual rechecks", () => {
    for (const spec of DEFAULT_COLLECTORS) {
      expect(spec.eligibleTriggers.includes("manual")).toBe(spec.eligibleTriggers.includes("deploy"));
    }
  });
});
});

describe("provider collectors name their transport", () => {
  it("maps each provider collector to the transport its failures are recorded under", () => {
    const byId = Object.fromEntries(DEFAULT_COLLECTORS.map((c) => [c.id, c.transport ?? null]));
    expect(byId).toEqual({
      "supabase-scan": null, "supabase-management": "supabase-management", "postgres-direct": "postgres-direct",
      "vercel-env": "vercel", "app-surface": "app-surface",
    });
  });
});
