import { describe, it, expect, vi, beforeEach } from "vitest";

const decryptMock = vi.fn();
const listProjectsMock = vi.fn();
const listProjectEnvMock = vi.fn();
const selectChainMock = vi.fn();
const insertMock = vi.fn();

vi.mock("@/lib/crypto", () => ({ decrypt: decryptMock }));
vi.mock("./vercel", () => ({
  listProjects: listProjectsMock,
  listProjectEnv: listProjectEnvMock,
}));
vi.mock("@/lib/supabase", () => ({
  getSupabaseAdmin: () => ({
    from: (table: string) => {
      if (table !== "deep_findings") throw new Error(`unexpected table ${table}`);
      return {
        select: () => ({
          eq: () => ({
            eq: () => ({
              is: selectChainMock,
            }),
          }),
        }),
        insert: insertMock,
      };
    },
  }),
}));

const { runVercelEnvAudit } = await import("./vercelRun");

describe("runVercelEnvAudit", () => {
  beforeEach(() => {
    decryptMock.mockReset().mockReturnValue("plaintext-access-token");
    listProjectsMock.mockReset();
    listProjectEnvMock.mockReset();
    selectChainMock.mockReset().mockResolvedValue({ data: [] });
    insertMock.mockReset().mockResolvedValue({ data: null, error: null });
  });

  it("decrypts the stored token before calling the Vercel API", async () => {
    listProjectsMock.mockResolvedValue([]);
    await runVercelEnvAudit("user-1", "cipher-text", null);
    expect(decryptMock).toHaveBeenCalledWith("cipher-text");
    expect(listProjectsMock).toHaveBeenCalledWith("plaintext-access-token", null);
  });

  it("audits every project's env and persists only findings not already active", async () => {
    listProjectsMock.mockResolvedValue([{ id: "p1", name: "site-one" }]);
    listProjectEnvMock.mockResolvedValue([
      { key: "NEXT_PUBLIC_SECRET_TOKEN", value: "a-long-enough-secret-value-here" },
    ]);
    selectChainMock.mockResolvedValue({ data: [] });

    const result = await runVercelEnvAudit("user-1", "cipher", null);

    expect(result.total).toBe(1);
    expect(result.newCount).toBe(1);
    expect(insertMock).toHaveBeenCalledTimes(1);
    const inserted = insertMock.mock.calls[0][0];
    expect(inserted).toHaveLength(1);
    expect(inserted[0]).toMatchObject({
      user_id: "user-1",
      source: "vercel",
      finding_id: "vercel:site-one:NEXT_PUBLIC_SECRET_TOKEN:client_exposed_secret",
      severity: "CRITICAL",
    });
  });

  it("does not re-insert a finding that is already active", async () => {
    listProjectsMock.mockResolvedValue([{ id: "p1", name: "site-one" }]);
    listProjectEnvMock.mockResolvedValue([
      { key: "NEXT_PUBLIC_SECRET_TOKEN", value: "a-long-enough-secret-value-here" },
    ]);
    selectChainMock.mockResolvedValue({
      data: [{ finding_id: "vercel:site-one:NEXT_PUBLIC_SECRET_TOKEN:client_exposed_secret" }],
    });

    const result = await runVercelEnvAudit("user-1", "cipher", null);

    expect(result.total).toBe(1);
    expect(result.newCount).toBe(0);
    expect(insertMock).not.toHaveBeenCalled();
  });

  it("skips a project whose env read fails without failing the whole pass", async () => {
    listProjectsMock.mockResolvedValue([
      { id: "p1", name: "broken-project" },
      { id: "p2", name: "healthy-project" },
    ]);
    listProjectEnvMock.mockImplementation(async (_token: string, projectId: string) => {
      if (projectId === "p1") throw new Error("Vercel env read HTTP 404");
      return [{ key: "NEXT_PUBLIC_SECRET_TOKEN", value: "a-long-enough-secret-value-here" }];
    });

    const result = await runVercelEnvAudit("user-1", "cipher", null);

    expect(result.total).toBe(1);
    expect(result.findings[0].id).toContain("healthy-project");
  });

  it("caps processing at the first 20 projects", async () => {
    const projects = Array.from({ length: 25 }, (_, i) => ({ id: `p${i}`, name: `proj-${i}` }));
    listProjectsMock.mockResolvedValue(projects);
    listProjectEnvMock.mockResolvedValue([]);

    await runVercelEnvAudit("user-1", "cipher", null);

    expect(listProjectEnvMock).toHaveBeenCalledTimes(20);
  });

  it("returns zero counts and does not call insert when there are no findings", async () => {
    listProjectsMock.mockResolvedValue([{ id: "p1", name: "clean-project" }]);
    listProjectEnvMock.mockResolvedValue([{ key: "NEXT_PUBLIC_SUPABASE_ANON_KEY", value: "eyJlong" }]);

    const result = await runVercelEnvAudit("user-1", "cipher", null);

    expect(result.total).toBe(0);
    expect(result.newCount).toBe(0);
    expect(insertMock).not.toHaveBeenCalled();
  });
});
