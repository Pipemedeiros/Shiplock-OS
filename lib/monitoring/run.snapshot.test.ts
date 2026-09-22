import { describe, it, expect, vi, beforeEach } from "vitest";
import type { CollectorSpec } from "./registry";

// Guards the one genuinely new behaviour the registry refactor introduced: a
// pass where every snapshot-producing collector failed must carry the prior
// state forward while recording failed coverage.
//
// Writing an empty one instead would read as "everything got fixed", and worse,
// make every real finding look brand new on the next successful pass — a burst
// of duplicate alerts for problems that never went away. Silence beats a wrong
// snapshot. Before the refactor this could not happen (the scan threw and took
// the whole pass with it); now that collectors are isolated, it can, so it needs
// an explicit test.

const insertMock = vi.fn();
const alertMock = vi.fn();
const saveFactsMock = vi.fn();
const profileUpdateMock = vi.fn();
let snapshotError: { message: string } | null = null;

vi.mock("@/lib/crypto", () => ({ decrypt: () => "anon-key" }));
vi.mock("@/lib/graph/graphRun", () => ({ saveFacts: saveFactsMock }));
vi.mock("./alerts", () => ({ sendNewFindingsAlert: alertMock }));
vi.mock("@/lib/supabase", () => ({
  getSupabaseAdmin: () => ({
    from: (table: string) => ({
      select: () => ({
        eq: () => ({
          order: () => ({
            limit: () => ({ maybeSingle: async () => ({ data: { findings: [{ id: "old" }] } }) }),
          }),
        }),
      }),
      insert: (row: unknown) => {
        if (table === "monitoring_snapshots") insertMock(row);
        return Promise.resolve({ error: snapshotError });
      },
      update: () => ({
        eq: () => {
          profileUpdateMock();
          return { then: (r: (v: unknown) => unknown) => r({ error: null }) };
        },
      }),
    }),
  }),
}));

const { runMonitoringPass, runMonitoringPassForWorker } = await import("./run");

const profile = {
  id: "u1",
  email: "a@b.com",
  monitored_project_url: "https://p.supabase.co",
  monitored_anon_key_encrypted: "enc",
  monitored_app_url: "https://app.example.com",
};

function spec(over: Partial<CollectorSpec> & Pick<CollectorSpec, "id">): CollectorSpec {
  return {
    layer: "db",
    eligibleTriggers: ["hourly", "deploy", "scheduled_48h"],
    timeoutMs: 1_000,
    run: async () => ({}),
    ...over,
  };
}

describe("runMonitoringPass — snapshot integrity", () => {
  beforeEach(() => {
    insertMock.mockReset();
    alertMock.mockReset();
    saveFactsMock.mockReset();
    profileUpdateMock.mockReset();
    snapshotError = null;
  });

  it("carries the previous snapshot when every snapshot-producing collector failed", async () => {
    const broken = spec({
      id: "broken",
      run: async () => {
        throw new Error("scan failed");
      },
    });

    const result = await runMonitoringPass(profile, "scheduled_48h", [broken]);

    expect(insertMock).toHaveBeenCalledWith(expect.objectContaining({
      findings: [{ id: "old" }],
      collectors: [expect.objectContaining({ id: "broken", status: "failed" })],
    }));
    expect(profileUpdateMock).not.toHaveBeenCalled();
    expect(result.newFindingsCount).toBe(0);
  });

  it("does not alert on 'resolved' findings that were merely never re-checked", async () => {
    // Previous snapshot had a finding; this pass collects nothing. Without the
    // guard the diff would treat the empty result as everything being fixed.
    const broken = spec({
      id: "broken",
      run: async () => {
        throw new Error("scan failed");
      },
    });

    await runMonitoringPass(profile, "scheduled_48h", [broken]);

    expect(alertMock).not.toHaveBeenCalled();
  });

  it("writes a snapshot with collector provenance when a collector succeeds", async () => {
    const ok = spec({
      id: "ok-collector",
      run: async () => ({ snapshotFindings: [{ id: "old" }] as never }),
    });

    await runMonitoringPass(profile, "scheduled_48h", [ok]);

    expect(insertMock).toHaveBeenCalledTimes(1);
    const row = insertMock.mock.calls[0][0] as { collectors: { id: string; status: string }[] };
    expect(row.collectors).toEqual([
      expect.objectContaining({ id: "ok-collector", status: "ok" }),
    ]);
  });

  it("records a failed collector in provenance, so history shows what was NOT checked", async () => {
    const ok = spec({ id: "ok", run: async () => ({ snapshotFindings: [] }) });
    const bad = spec({
      id: "bad",
      run: async () => {
        throw new Error("boom");
      },
    });

    await runMonitoringPass(profile, "scheduled_48h", [ok, bad]);

    const row = insertMock.mock.calls[0][0] as { collectors: { id: string; status: string }[] };
    expect(row.collectors).toEqual([
      expect.objectContaining({ id: "ok", status: "ok" }),
      expect.objectContaining({ id: "bad", status: "failed" }),
    ]);
  });

  it("returns fresh findings before asking the worker to retry a failed coverage write", async () => {
    snapshotError = { message: "storage unavailable" };
    const finding = { id: "new", severity: "CRITICAL", title: "New", consequence: "Risk" } as const;
    const ok = spec({ id: "ok", run: async () => ({ newFindings: [finding] }) });
    await expect(runMonitoringPassForWorker(profile, "scheduled_48h", [ok])).resolves.toMatchObject({
      newFindings: [finding],
      writesSucceeded: false,
    });
  });

  it("persists graph facts a collector contributed", async () => {
    const withFacts = spec({
      id: "with-facts",
      run: async () => ({
        snapshotFindings: [],
        facts: { collector: "db" as const, facts: { scanTables: [{ name: "t", rlsEnabled: true }] }, merge: true },
      }),
    });

    await runMonitoringPass(profile, "scheduled_48h", [withFacts]);

    expect(saveFactsMock).toHaveBeenCalledWith(
      "u1",
      "db",
      { scanTables: [{ name: "t", rlsEnabled: true }] },
      { merge: true }
    );
  });

  it("alerts on pre-diffed findings from a self-diffing collector", async () => {
    const selfDiffing = spec({
      id: "app-surface-like",
      run: async () => ({ newFindings: [{ id: "leak", severity: "CRITICAL" }] as never }),
    });
    const scan = spec({ id: "scan", run: async () => ({ snapshotFindings: [] }) });

    const result = await runMonitoringPass(profile, "scheduled_48h", [scan, selfDiffing]);

    expect(result.newFindingsCount).toBe(1);
    expect(alertMock).toHaveBeenCalled();
  });
});
