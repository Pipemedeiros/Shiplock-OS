import { describe, it, expect, vi, beforeEach } from "vitest";

const scanProjectMock = vi.fn();
const scanCriticalChecksMock = vi.fn();
const exposedScanMock = vi.fn();
const alertMock = vi.fn();
const snapshotSelectMock = vi.fn();
const snapshotInsertMock = vi.fn();
const profileUpdateMock = vi.fn();

vi.mock("@/lib/scanner", () => ({
  scanProject: scanProjectMock,
  scanCriticalChecks: scanCriticalChecksMock,
}));
vi.mock("@/lib/crypto", () => ({ decrypt: (v: string) => `plain-${v}` }));
vi.mock("./alerts", () => ({ sendNewFindingsAlert: alertMock }));
vi.mock("@/lib/security/exposedPathsRun", () => ({ runExposedPathScan: exposedScanMock }));
vi.mock("./findings", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./findings")>();
  return actual;
});
vi.mock("@/lib/supabase", () => ({
  getSupabaseAdmin: () => ({
    from: (table: string) => {
      if (table === "monitoring_snapshots") {
        return {
          select: () => ({
            eq: () => ({ order: () => ({ limit: () => ({ maybeSingle: snapshotSelectMock }) }) }),
          }),
          insert: snapshotInsertMock,
        };
      }
      if (table === "user_profiles") {
        return { update: () => ({ eq: profileUpdateMock }) };
      }
      throw new Error(`unexpected table ${table}`);
    },
  }),
}));

const { runMonitoringPass } = await import("./run");

// A ScanResult shaped just enough for extractFindings: a clean project with no
// findings of any kind. Cast because these tests exercise runMonitoringPass's
// orchestration, not the scanner's full result shape.
const cleanScan = { tables: [], checks: [] } as unknown as Awaited<ReturnType<typeof scanProjectMock>>;

/** A clean scan with one RLS-disabled table, i.e. one CRITICAL finding. */
const scanWithFinding = { tables: [{ name: "orders", rlsEnabled: false, rlsReadable: true }], checks: [] } as unknown as typeof cleanScan;

const profile = (over: Record<string, unknown> = {}) => ({
  id: "u1",
  email: "founder@example.com",
  monitored_project_url: "https://abc.supabase.co",
  monitored_anon_key_encrypted: "cipher",
  ...over,
});

describe("runMonitoringPass — app-surface scan gating", () => {
  beforeEach(() => {
    scanProjectMock.mockReset().mockResolvedValue(cleanScan);
    scanCriticalChecksMock.mockReset().mockResolvedValue(cleanScan);
    exposedScanMock.mockReset().mockResolvedValue({ total: 0, newCount: 0, resolvedCount: 0, newFindings: [] });
    alertMock.mockReset().mockResolvedValue(undefined);
    snapshotSelectMock.mockReset().mockResolvedValue({ data: null });
    snapshotInsertMock.mockReset().mockReturnValue(Promise.resolve({ error: null }));
    profileUpdateMock.mockReset().mockReturnValue(Promise.resolve({ error: null }));
  });

  it("runs the app-surface scan on the 48h deep pass", async () => {
    await runMonitoringPass(profile({ monitored_app_url: "https://app.example.com" }), "scheduled_48h");
    expect(exposedScanMock).toHaveBeenCalledWith("u1", "https://app.example.com");
  });

  // The bundle audit downloads real chunks. That's the wrong weight for a pass
  // that fires every hour, and a bundle only changes on deploy anyway.
  it("does NOT run it on the hourly pass, which must stay lightweight", async () => {
    await runMonitoringPass(profile({ monitored_app_url: "https://app.example.com" }), "hourly");
    expect(exposedScanMock).not.toHaveBeenCalled();
    expect(scanCriticalChecksMock).toHaveBeenCalled();
    expect(scanProjectMock).not.toHaveBeenCalled();
  });

  it("skips it when the customer never gave us an app URL", async () => {
    await runMonitoringPass(profile(), "scheduled_48h");
    expect(exposedScanMock).not.toHaveBeenCalled();
    // The Supabase-side scan still runs — no app URL is not a blocked pass.
    expect(scanProjectMock).toHaveBeenCalled();
  });

  it("skips it on an explicitly null app URL", async () => {
    await runMonitoringPass(profile({ monitored_app_url: null }), "scheduled_48h");
    expect(exposedScanMock).not.toHaveBeenCalled();
  });

  it("alerts on a newly-shipped secret the same pass we find it", async () => {
    exposedScanMock.mockResolvedValue({
      total: 1,
      newCount: 1,
      resolvedCount: 0,
      newFindings: [
        {
          id: "bundle:shipped_secret:supabase_service_role_jwt",
          severity: "CRITICAL",
          title: "service role key in bundle",
          consequence: "rotate it",
        },
      ],
    });

    const result = await runMonitoringPass(
      profile({ monitored_app_url: "https://app.example.com" }),
      "scheduled_48h"
    );

    expect(result.newFindingsCount).toBe(1);
    const [, , findings] = alertMock.mock.calls[0];
    expect(findings).toHaveLength(1);
    expect(findings[0].id).toBe("bundle:shipped_secret:supabase_service_role_jwt");
  });

  it("sends ONE email covering both lanes, not two", async () => {
    scanProjectMock.mockResolvedValue(scanWithFinding);
    exposedScanMock.mockResolvedValue({
      total: 1,
      newCount: 1,
      resolvedCount: 0,
      newFindings: [{ id: "bundle:x", severity: "CRITICAL", title: "t", consequence: "c" }],
    });

    const result = await runMonitoringPass(
      profile({ monitored_app_url: "https://app.example.com" }),
      "scheduled_48h"
    );

    expect(alertMock).toHaveBeenCalledTimes(1);
    expect(result.newFindingsCount).toBe(2);
  });

  // The Supabase-side snapshot is the load-bearing part of a pass. An app that
  // is down, slow, or behind auth must not cost the customer their DB monitoring.
  it("still completes the pass when the app-surface scan throws", async () => {
    exposedScanMock.mockRejectedValue(new Error("ECONNREFUSED"));

    const result = await runMonitoringPass(
      profile({ monitored_app_url: "https://app.example.com" }),
      "scheduled_48h"
    );

    expect(result.newFindingsCount).toBe(0);
    expect(snapshotInsertMock).toHaveBeenCalled();
  });

  it("writes a snapshot and refreshes last_monitored_at on a deep pass", async () => {
    await runMonitoringPass(profile(), "scheduled_48h");
    expect(snapshotInsertMock).toHaveBeenCalled();
    expect(profileUpdateMock).toHaveBeenCalled();
  });

  it("does not refresh last_monitored_at on the hourly pass", async () => {
    await runMonitoringPass(profile(), "hourly");
    expect(profileUpdateMock).not.toHaveBeenCalled();
  });

  it("sends no email when nothing is new", async () => {
    await runMonitoringPass(profile({ monitored_app_url: "https://app.example.com" }), "scheduled_48h");
    expect(alertMock).not.toHaveBeenCalled();
  });

  it("sends no email when the profile has no address", async () => {
    exposedScanMock.mockResolvedValue({
      total: 1,
      newCount: 1,
      resolvedCount: 0,
      newFindings: [{ id: "bundle:x", severity: "CRITICAL", title: "t", consequence: "c" }],
    });

    await runMonitoringPass(
      profile({ email: null, monitored_app_url: "https://app.example.com" }),
      "scheduled_48h"
    );

    expect(alertMock).not.toHaveBeenCalled();
  });
});
