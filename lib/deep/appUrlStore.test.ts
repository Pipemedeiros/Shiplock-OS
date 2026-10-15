import { beforeEach, describe, expect, it, vi } from "vitest";

const db = vi.hoisted(() => ({ profile: {} as Record<string, unknown>, repos: [] as Record<string, unknown>[], updates: [] as unknown[] }));
const gh = vi.hoisted(() => ({ token: vi.fn(), homepage: {} as Record<string, string | null>, fail: false }));
const guard = vi.hoisted(() => ({ assert: vi.fn() }));
vi.mock("@/lib/deep/github", () => ({ getInstallationToken: gh.token }));
vi.stubGlobal("fetch", vi.fn(async (url: string) => {
  if (gh.fail) throw new Error("down");
  const name = url.replace("https://api.github.com/repos/", "");
  return new Response(JSON.stringify({ homepage: gh.homepage[name] ?? null }));
}));
vi.mock("@/lib/security/ssrfGuard", () => ({ assertPublicHttpsUrl: guard.assert }));
vi.mock("@/lib/supabase", () => ({ getSupabaseAdmin: () => ({
  from: (table: string) => {
    const q: Record<string, unknown> = {};
    Object.assign(q, {
      select: () => q, eq: () => q,
      maybeSingle: async () => ({ data: table === "user_profiles" ? db.profile : null, error: null }),
      update: (patch: unknown) => { db.updates.push(patch); return { eq: async () => ({ error: null }) }; },
      then: (res: (v: unknown) => unknown) => Promise.resolve({ data: table === "repositories" ? db.repos : [], error: null }).then(res),
    });
    return q;
  },
}) }));

const { clearAppUrl, getAppUrlState, setAppUrl } = await import("./appUrlStore");

beforeEach(() => {
  vi.clearAllMocks(); db.updates = [];
  db.profile = { github_installation_id: 42, monitored_app_url: null };
  db.repos = [{ full_name: "acme/app" }, { full_name: "acme/docs" }];
  gh.token.mockResolvedValue("t");
  gh.fail = false;
  gh.homepage = { "acme/app": "https://app.acme.com/x", "acme/docs": "https://github.com/acme/docs", "acme/other": "https://other.acme.com" };
  guard.assert.mockResolvedValue(undefined);
});

describe("the app address", () => {
  it("suggests the selected repositories' homepages only, as origins", async () => {
    expect(await getAppUrlState("u1")).toEqual({ current: null, suggestions: [{ repository: "acme/app", url: "https://app.acme.com" }] });
  });

  it("still answers when GitHub cannot be read, with no suggestions", async () => {
    gh.token.mockRejectedValue(new Error("down"));
    db.profile = { github_installation_id: 42, monitored_app_url: "https://acme.com" };
    expect(await getAppUrlState("u1")).toEqual({ current: "https://acme.com", suggestions: [] });
  });

  it("saves the origin of a public https address after the SSRF guard", async () => {
    expect(await setAppUrl("u1", "https://acme.com/login?next=1")).toBe("https://acme.com");
    expect(guard.assert).toHaveBeenCalledWith("https://acme.com");
    expect(db.updates).toEqual([{ monitored_app_url: "https://acme.com" }]);
  });

  it.each(["http://acme.com", "https://", "javascript:alert(1)", "https://user:pw@acme.com"])("refuses %s before saving", async (bad) => {
    await expect(setAppUrl("u1", bad)).rejects.toThrow("invalid_url");
    expect(db.updates).toEqual([]);
  });

  it("refuses an address the SSRF guard blocks (a private host)", async () => {
    guard.assert.mockRejectedValue(new Error("private"));
    await expect(setAppUrl("u1", "https://intranet.acme.com")).rejects.toThrow("invalid_url");
    expect(db.updates).toEqual([]);
  });

  it("forgets the address", async () => {
    await clearAppUrl("u1");
    expect(db.updates).toEqual([{ monitored_app_url: null }]);
  });
});
