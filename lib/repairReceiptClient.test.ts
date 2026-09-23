import { afterEach, describe, expect, it, vi } from "vitest";
import { repairMessage, waitForRepair } from "./repairReceiptClient";

// 3F-C2d-3: the dashboard follows a queued fix click to its real outcome.
afterEach(() => vi.unstubAllGlobals());

const respond = (...bodies: unknown[]) => {
  const fetchMock = vi.fn();
  for (const body of bodies) fetchMock.mockResolvedValueOnce(new Response(JSON.stringify(body), { status: 200 }));
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
};

describe("waitForRepair", () => {
  it("polls the caller's receipt until the PR is opened", async () => {
    const fetchMock = respond({ status: "queued", url: null, failure: null }, { status: "opened", url: "https://github.com/acme/app/pull/9", failure: null });
    expect(await waitForRepair("r-1", { intervalMs: 0 })).toEqual({ status: "opened", url: "https://github.com/acme/app/pull/9", failure: null });
    expect(fetchMock).toHaveBeenCalledWith("/api/fix/receipts/r-1", { cache: "no-store" });
  });

  it("stops on a permanent failure", async () => {
    respond({ status: "failed", url: null, failure: "not_fixable" });
    expect((await waitForRepair("r-1", { intervalMs: 0 })).status).toBe("failed");
  });

  it("returns the last state when the time budget runs out", async () => {
    respond({ status: "uncertain", url: null, failure: "delivery_unconfirmed" }, { status: "uncertain", url: null, failure: "delivery_unconfirmed" });
    expect((await waitForRepair("r-1", { attempts: 2, intervalMs: 0 })).status).toBe("uncertain");
  });
});

describe("repairMessage", () => {
  it("says plainly what happened, without dashes", () => {
    for (const view of [
      { status: "failed", url: null, failure: "not_fixable" },
      { status: "failed", url: null, failure: "repository_unavailable" },
      { status: "failed", url: null, failure: "finding_unavailable" },
      { status: "failed", url: null, failure: "github_rejected" },
      { status: "uncertain", url: null, failure: "delivery_unconfirmed" },
      { status: "queued", url: null, failure: null },
    ] as const) {
      const message = repairMessage(view);
      expect(message.length).toBeGreaterThan(10);
      expect(message).not.toMatch(/[—–]/);
    }
  });
});
