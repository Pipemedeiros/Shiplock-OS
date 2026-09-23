import { describe, it, expect, vi, beforeEach } from "vitest";

const probeMock = vi.fn();
const auditMock = vi.fn();
const emailMock = vi.fn();
const selectChainMock = vi.fn();
const insertMock = vi.fn();
const updateInMock = vi.fn();
const updateSpy = vi.fn();

vi.mock("./exposedPaths", () => ({ probeExposedPaths: probeMock }));
vi.mock("./bundleAudit", () => ({ auditShippedBundle: auditMock }));
// Mocked so the suite never performs real DNS lookups.
vi.mock("./emailAuth", () => ({ auditEmailAuth: emailMock, nodeTxtResolver: vi.fn() }));
vi.mock("@/lib/supabase", () => ({
  getSupabaseAdmin: () => ({
    from: (table: string) => {
      if (table !== "deep_findings") throw new Error(`unexpected table ${table}`);
      return {
        select: () => ({ eq: () => ({ eq: () => ({ is: selectChainMock }) }) }),
        insert: insertMock,
        update: (patch: unknown) => {
          updateSpy(patch);
          return { eq: () => ({ eq: () => ({ is: () => ({ in: updateInMock }) }) }) };
        },
      };
    },
  }),
}));

const { runExposedPathScan } = await import("./exposedPathsRun");

const finding = (id: string) => ({
  id,
  severity: "CRITICAL" as const,
  title: `t-${id}`,
  consequence: `c-${id}`,
});

describe("runExposedPathScan", () => {
  beforeEach(() => {
    probeMock.mockReset().mockResolvedValue([]);
    auditMock.mockReset().mockResolvedValue([]);
    emailMock.mockReset().mockResolvedValue([]);
    selectChainMock.mockReset().mockResolvedValue({ data: [] });
    insertMock.mockReset().mockResolvedValue({ data: null, error: null });
    updateInMock.mockReset().mockResolvedValue({ data: null, error: null });
    updateSpy.mockReset();
  });

  it("runs all three collectors against the app URL", async () => {
    await runExposedPathScan("u1", "https://app.example.com");
    expect(probeMock).toHaveBeenCalledWith("https://app.example.com", undefined);
    expect(auditMock).toHaveBeenCalledWith("https://app.example.com", undefined);
    expect(emailMock).toHaveBeenCalledWith("https://app.example.com", expect.anything());
  });

  it("persists email-auth findings alongside the others", async () => {
    emailMock.mockResolvedValue([finding("email_auth:dmarc_missing")]);
    const result = await runExposedPathScan("u1", "https://app.example.com");
    expect(result.newCount).toBe(1);
    const rows = insertMock.mock.calls[0][0] as { finding_id: string }[];
    expect(rows[0].finding_id).toBe("email_auth:dmarc_missing");
  });

  it("keeps the other two collectors' findings when the email audit throws", async () => {
    emailMock.mockRejectedValue(new Error("ETIMEOUT"));
    probeMock.mockResolvedValue([finding("exposed:git_exposed")]);
    auditMock.mockResolvedValue([finding("bundle:shipped_secret:aws_access_key")]);
    const result = await runExposedPathScan("u1", "https://app.example.com");
    expect(result.newCount).toBe(2);
  });

  it("persists findings from both sources under one source label", async () => {
    probeMock.mockResolvedValue([finding("exposed:git_exposed")]);
    auditMock.mockResolvedValue([finding("bundle:shipped_secret:supabase_service_role_jwt")]);

    const result = await runExposedPathScan("u1", "https://app.example.com");

    expect(result.total).toBe(2);
    expect(result.newCount).toBe(2);
    expect(result.resolvedCount).toBe(0);
    // Returned so the monitoring pass can alert on them the same hour we find
    // them, rather than waiting for the weekly digest.
    expect(result.newFindings.map((f) => f.id).sort()).toEqual([
      "bundle:shipped_secret:supabase_service_role_jwt",
      "exposed:git_exposed",
    ]);
    const rows = insertMock.mock.calls[0][0] as { finding_id: string; source: string }[];
    expect(rows.map((r) => r.finding_id).sort()).toEqual([
      "bundle:shipped_secret:supabase_service_role_jwt",
      "exposed:git_exposed",
    ]);
    expect(rows.every((r) => r.source === "exposed-path")).toBe(true);
  });

  it("inserts only findings that aren't already open", async () => {
    selectChainMock.mockResolvedValue({ data: [{ finding_id: "exposed:git_exposed" }] });
    probeMock.mockResolvedValue([finding("exposed:git_exposed"), finding("exposed:ssh_key_exposed")]);

    const result = await runExposedPathScan("u1", "https://app.example.com");

    expect(result.newCount).toBe(1);
    const rows = insertMock.mock.calls[0][0] as { finding_id: string }[];
    expect(rows).toHaveLength(1);
    expect(rows[0].finding_id).toBe("exposed:ssh_key_exposed");
  });

  // The reason archiving was added: a D7 finding tells the customer to rotate
  // the key. If it survives the rotation, we show CRITICAL after they did the
  // one thing we asked.
  it("archives a finding that no longer reproduces", async () => {
    selectChainMock.mockResolvedValue({
      data: [{ finding_id: "bundle:shipped_secret:supabase_service_role_jwt" }],
    });

    const result = await runExposedPathScan("u1", "https://app.example.com");

    expect(result.resolvedCount).toBe(1);
    expect(updateInMock).toHaveBeenCalledWith("finding_id", [
      "bundle:shipped_secret:supabase_service_role_jwt",
    ]);
    expect(updateSpy.mock.calls[0][0]).toHaveProperty("archived_at");
  });

  it("does not archive a finding that still reproduces", async () => {
    selectChainMock.mockResolvedValue({ data: [{ finding_id: "exposed:git_exposed" }] });
    probeMock.mockResolvedValue([finding("exposed:git_exposed")]);

    const result = await runExposedPathScan("u1", "https://app.example.com");

    expect(result.resolvedCount).toBe(0);
    expect(updateInMock).not.toHaveBeenCalled();
    expect(insertMock).not.toHaveBeenCalled();
  });

  it("archives and inserts in the same pass when one is fixed and another appears", async () => {
    selectChainMock.mockResolvedValue({ data: [{ finding_id: "exposed:git_exposed" }] });
    auditMock.mockResolvedValue([finding("bundle:source_map_exposed:with_content")]);

    const result = await runExposedPathScan("u1", "https://app.example.com");

    expect(result.total).toBe(1);
    expect(result.newCount).toBe(1);
    expect(result.resolvedCount).toBe(1);
    expect(result.newFindings).toHaveLength(1);
  });

  it("writes nothing at all when there is nothing to change", async () => {
    await runExposedPathScan("u1", "https://app.example.com");
    expect(insertMock).not.toHaveBeenCalled();
    expect(updateInMock).not.toHaveBeenCalled();
  });

  // One collector failing must not archive the other's still-valid findings.
  it("keeps the bundle audit's findings when the path probes throw", async () => {
    probeMock.mockRejectedValue(new Error("network"));
    auditMock.mockResolvedValue([finding("bundle:shipped_secret:aws_access_key")]);

    const result = await runExposedPathScan("u1", "https://app.example.com");

    expect(result.newCount).toBe(1);
  });

  it("keeps the path probes' findings when the bundle audit throws", async () => {
    auditMock.mockRejectedValue(new Error("network"));
    probeMock.mockResolvedValue([finding("exposed:git_exposed")]);

    const result = await runExposedPathScan("u1", "https://app.example.com");

    expect(result.newCount).toBe(1);
  });

  it("returns no new findings when everything found is already open", async () => {
    selectChainMock.mockResolvedValue({ data: [{ finding_id: "exposed:git_exposed" }] });
    probeMock.mockResolvedValue([finding("exposed:git_exposed")]);

    const result = await runExposedPathScan("u1", "https://app.example.com");

    expect(result.newFindings).toEqual([]);
  });

  it("tolerates a null select result", async () => {
    selectChainMock.mockResolvedValue({ data: null });
    probeMock.mockResolvedValue([finding("exposed:git_exposed")]);

    const result = await runExposedPathScan("u1", "https://app.example.com");

    expect(result.newCount).toBe(1);
  });
});

describe("runExposedPathScan — 3F-C2b-2 cancellation", () => {
  beforeEach(() => {
    selectChainMock.mockReset().mockResolvedValue({ data: [{ finding_id: "exposed:env" }] });
    insertMock.mockReset().mockResolvedValue({ data: null, error: null });
    updateInMock.mockReset().mockResolvedValue({ data: null, error: null });
    updateSpy.mockReset();
    auditMock.mockReset().mockResolvedValue([]);
    emailMock.mockReset().mockResolvedValue([]);
  });

  it("forwards the signal and never archives findings from a cancelled, empty pass", async () => {
    const controller = new AbortController();
    probeMock.mockReset().mockImplementation(async () => {
      controller.abort(new Error("collector timed out"));
      return [];
    });
    await expect(runExposedPathScan("u1", "https://app.example.com", { signal: controller.signal }))
      .rejects.toThrow("collector timed out");
    expect(probeMock).toHaveBeenCalledWith("https://app.example.com", controller.signal);
    expect(auditMock).toHaveBeenCalledWith("https://app.example.com", controller.signal);
    expect(updateSpy).not.toHaveBeenCalled();
    expect(updateInMock).not.toHaveBeenCalled();
    expect(insertMock).not.toHaveBeenCalled();
  });
});
