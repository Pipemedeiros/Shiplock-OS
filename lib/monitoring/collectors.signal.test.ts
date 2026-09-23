import { beforeEach, describe, expect, it, vi } from "vitest";
import type { CollectorContext } from "./registry";
import type { MonitoredProfile } from "./types";

// 3F-C2b: the registry's per-collector signal is useless unless each provider
// collector hands it to the transport that actually performs the reads.
const runners = vi.hoisted(() => ({
  policy: vi.fn(), postgres: vi.fn(), vercel: vi.fn(),
}));
vi.mock("@/lib/deep/supabaseMgmtRun", () => ({ runPolicyScan: runners.policy }));
vi.mock("@/lib/deep/postgresDirectRun", () => ({ runDirectPostgresScan: runners.postgres }));
vi.mock("@/lib/deep/vercelRun", () => ({ runVercelEnvAudit: runners.vercel }));

import { directPostgresCollector, supabaseManagementCollector, vercelEnvCollector } from "./collectors";

const signal = new AbortController().signal;
const ctx = (over: Partial<MonitoredProfile>): CollectorContext => ({
  profile: { id: "user-1", email: "founder@example.com", ...over } as MonitoredProfile,
  anonKey: null, triggerSource: "scheduled_48h", previousFindings: [], signal,
});

beforeEach(() => {
  runners.policy.mockReset().mockResolvedValue({ ok: true, findings: 0, newFindings: [] });
  runners.postgres.mockReset().mockResolvedValue({ ok: true, findings: 0, newFindings: [] });
  runners.vercel.mockReset().mockResolvedValue({ newFindings: [] });
});

describe("provider collectors forward the registry signal", () => {
  it("Supabase Management", async () => {
    await supabaseManagementCollector.run(ctx({}));
    expect(runners.policy).toHaveBeenCalledWith("user-1", { signal });
  });

  it("direct Postgres", async () => {
    await directPostgresCollector.run(ctx({}));
    expect(runners.postgres).toHaveBeenCalledWith("user-1", { signal });
  });

  it("Vercel environment audit", async () => {
    await vercelEnvCollector.run(ctx({ vercel_access_token_encrypted: "enc", vercel_team_id: "team" } as Partial<MonitoredProfile>));
    expect(runners.vercel).toHaveBeenCalledWith("user-1", "enc", "team", { signal });
  });
});
