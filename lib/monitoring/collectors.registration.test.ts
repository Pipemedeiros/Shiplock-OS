import { describe, expect, it } from "vitest";
import { DEFAULT_COLLECTORS, directPostgresCollector } from "./collectors";
import type { CollectorContext } from "./registry";
import type { MonitoredProfile } from "./types";

// This file exists because of a bug class, not a feature.
//
// CLAUDE.md records three separate occasions where a collector was written,
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
