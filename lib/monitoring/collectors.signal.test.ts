import { beforeEach, describe, expect, it, vi } from "vitest";
import type { CollectorContext } from "./registry";
import type { MonitoredProfile } from "./types";

// 3F-C2b: the registry's per-collector signal is useless unless each provider
// collector hands it to the transport that actually performs the reads.
const runners = vi.hoisted(() => ({
  policy: vi.fn(), postgres: vi.fn(), vercel: vi.fn(),
  scan: vi.fn(), critical: vi.fn(), exposed: vi.fn(),
}));
vi.mock("@/lib/scanner", () => ({ scanProject: runners.scan, scanCriticalChecks: runners.critical }));
vi.mock("@/lib/security/exposedPathsRun", () => ({ runExposedPathScan: runners.exposed }));
vi.mock("@/lib/deep/supabaseMgmtRun", () => ({ runPolicyScan: runners.policy }));
vi.mock("@/lib/deep/postgresDirectRun", () => ({ runDirectPostgresScan: runners.postgres }));
vi.mock("@/lib/deep/vercelRun", () => ({ runVercelEnvAudit: runners.vercel }));

import {
  appSurfaceCollector, directPostgresCollector, supabaseManagementCollector, supabaseScanCollector, vercelEnvCollector,
} from "./collectors";

const signal = new AbortController().signal;
const ctx = (over: Partial<MonitoredProfile>): CollectorContext => ({
  profile: { id: "user-1", email: "founder@example.com", ...over } as MonitoredProfile,
  anonKey: null, triggerSource: "scheduled_48h", previousFindings: [], signal,
});

beforeEach(() => {
  runners.policy.mockReset().mockResolvedValue({ ok: true, findings: 0, newFindings: [] });
  runners.postgres.mockReset().mockResolvedValue({ ok: true, findings: 0, newFindings: [] });
  runners.vercel.mockReset().mockResolvedValue({ newFindings: [] });
  runners.scan.mockReset().mockResolvedValue({ tables: [] });
  runners.critical.mockReset().mockResolvedValue({ tables: [] });
  runners.exposed.mockReset().mockResolvedValue({ newFindings: [] });
});

describe("provider collectors forward the registry signal", () => {
  it("Supabase Management", async () => {
    await supabaseManagementCollector.run(ctx({}));
    expect(runners.policy).toHaveBeenCalledWith("user-1", { signal });
  });

  it("direct Postgres", async () => {
    await directPostgresCollector.run(ctx({}));
    expect(runners.postgres).toHaveBeenCalledWith("user-1", { signal, commit: undefined });
  });

  it("Vercel environment audit", async () => {
    await vercelEnvCollector.run(ctx({ vercel_access_token_encrypted: "enc", vercel_connection_epoch: "e".repeat(64), vercel_team_id: "team" } as Partial<MonitoredProfile>));
    expect(runners.vercel).toHaveBeenCalledWith("user-1", "enc", "e".repeat(64), "team", { signal });
  });
});

describe("endpoint and app-surface collectors forward the registry signal", () => {
  const url = { monitored_project_url: "https://abc.supabase.co" } as Partial<MonitoredProfile>;
  it("full Supabase endpoint scan", async () => {
    await supabaseScanCollector.run({ ...ctx(url), anonKey: "anon" });
    expect(runners.scan).toHaveBeenCalledWith("https://abc.supabase.co", "anon", undefined, signal, expect.any(Array));
  });

  it("hourly critical subset", async () => {
    await supabaseScanCollector.run({ ...ctx(url), anonKey: "anon", triggerSource: "hourly" });
    expect(runners.critical).toHaveBeenCalledWith("https://abc.supabase.co", "anon", signal, expect.any(Array));
  });

  it("app surface", async () => {
    await appSurfaceCollector.run(ctx({ monitored_app_url: "https://app.example.com" } as Partial<MonitoredProfile>));
    expect(runners.exposed).toHaveBeenCalledWith("user-1", "https://app.example.com", { signal });
  });
});

describe("3F-C2c-2: provider collectors forward the fenced commit", () => {
  it("direct Postgres", async () => {
    const commit = vi.fn();
    await directPostgresCollector.run({ ...ctx({}), commit });
    expect(runners.postgres).toHaveBeenCalledWith("user-1", { signal, commit });
  });
});
