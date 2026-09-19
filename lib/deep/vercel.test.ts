import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// env.ts parses process.env ONCE at import time (correctly, matching how env
// vars behave in a real running process), so mutating process.env in
// beforeEach can't influence an already-imported env object. Mock @/lib/env
// directly instead, via a hoisted mutable object each test can adjust.
const { mockEnv } = vi.hoisted(() => ({
  mockEnv: {
    VERCEL_CLIENT_ID: "client-id-123" as string | undefined,
    VERCEL_CLIENT_SECRET: "client-secret-456" as string | undefined,
    NEXT_PUBLIC_APP_URL: "https://shiplock.dev",
  },
}));
vi.mock("@/lib/env", () => ({ env: mockEnv }));

const { exchangeCodeForToken, listProjects, listProjectEnv } = await import("./vercel");

function jsonResponse(body: unknown, ok = true, status = 200) {
  return { ok, status, json: async () => body } as Response;
}

describe("lib/deep/vercel", () => {
  const originalFetch = global.fetch;

  beforeEach(() => {
    mockEnv.VERCEL_CLIENT_ID = "client-id-123";
    mockEnv.VERCEL_CLIENT_SECRET = "client-secret-456";
  });

  afterEach(() => {
    global.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  describe("exchangeCodeForToken", () => {
    it("throws when VERCEL_CLIENT_ID/SECRET are unset", async () => {
      mockEnv.VERCEL_CLIENT_ID = undefined;
      mockEnv.VERCEL_CLIENT_SECRET = undefined;
      await expect(exchangeCodeForToken("some-code")).rejects.toThrow(
        "VERCEL_CLIENT_ID and VERCEL_CLIENT_SECRET must be set"
      );
    });

    it("posts the correct form body and parses a successful response", async () => {
      const fetchMock = vi.fn().mockResolvedValue(
        jsonResponse({ access_token: "tok_abc", team_id: "team_1", installation_id: "cfg_1" })
      );
      global.fetch = fetchMock as unknown as typeof fetch;

      const result = await exchangeCodeForToken("the-code");

      expect(result).toEqual({ accessToken: "tok_abc", teamId: "team_1", configurationId: "cfg_1" });
      const [url, init] = fetchMock.mock.calls[0];
      expect(url).toBe("https://api.vercel.com/v2/oauth/access_token");
      expect(init.method).toBe("POST");
      const body = init.body as URLSearchParams;
      expect(body.get("client_id")).toBe("client-id-123");
      expect(body.get("client_secret")).toBe("client-secret-456");
      expect(body.get("code")).toBe("the-code");
      expect(body.get("redirect_uri")).toBe("https://shiplock.dev/api/deep/vercel/callback");
    });

    it("defaults teamId/configurationId to null when absent from the response", async () => {
      global.fetch = vi.fn().mockResolvedValue(jsonResponse({ access_token: "tok_abc" })) as unknown as typeof fetch;
      const result = await exchangeCodeForToken("code");
      expect(result.teamId).toBeNull();
      expect(result.configurationId).toBeNull();
    });

    it("throws with the HTTP status on a non-ok response", async () => {
      global.fetch = vi.fn().mockResolvedValue(jsonResponse({}, false, 401)) as unknown as typeof fetch;
      await expect(exchangeCodeForToken("bad-code")).rejects.toThrow("Vercel token exchange HTTP 401");
    });
  });

  describe("listProjects", () => {
    it("requests without a teamId query param when teamId is null", async () => {
      const fetchMock = vi.fn().mockResolvedValue(jsonResponse({ projects: [] }));
      global.fetch = fetchMock as unknown as typeof fetch;
      await listProjects("token", null);
      expect(fetchMock.mock.calls[0][0]).toBe("https://api.vercel.com/v9/projects");
    });

    it("includes the teamId query param when provided", async () => {
      const fetchMock = vi.fn().mockResolvedValue(jsonResponse({ projects: [] }));
      global.fetch = fetchMock as unknown as typeof fetch;
      await listProjects("token", "team_9");
      expect(fetchMock.mock.calls[0][0]).toBe("https://api.vercel.com/v9/projects?teamId=team_9");
    });

    it("sends the bearer auth header and ignores unsupported extra fields", async () => {
      const fetchMock = vi.fn().mockResolvedValue(
        jsonResponse({ projects: [{ id: "p1", name: "site-one", extraField: "ignored" }] })
      );
      global.fetch = fetchMock as unknown as typeof fetch;
      const projects = await listProjects("secret-token", null);
      expect(fetchMock.mock.calls[0][1].headers.Authorization).toBe("Bearer secret-token");
      expect(projects).toEqual([{ id: "p1", name: "site-one" }]);
    });

    it("retains an explicit GitHub repository link as provenance", async () => {
      global.fetch = vi.fn().mockResolvedValue(jsonResponse({ projects: [{
        id: "p1", name: "site-one",
        link: { type: "github", org: "Acme", repo: "Web", repoId: 42 },
      }] })) as unknown as typeof fetch;
      expect(await listProjects("token", null)).toEqual([{
        id: "p1", name: "site-one",
        gitRepository: { type: "github", fullName: "Acme/Web", repoId: "42" },
      }]);
    });

    it("does not infer a GitHub link from malformed or non-GitHub metadata", async () => {
      global.fetch = vi.fn().mockResolvedValue(jsonResponse({ projects: [
        { id: "p1", name: "gitlab", link: { type: "gitlab", org: "Acme", repo: "Web" } },
        { id: "p2", name: "bad", link: { type: "github", org: "Acme/Other", repo: "Web" } },
      ] })) as unknown as typeof fetch;
      expect(await listProjects("token", null)).toEqual([
        { id: "p1", name: "gitlab" }, { id: "p2", name: "bad" },
      ]);
    });

    it("returns an empty array when the response has no projects field", async () => {
      global.fetch = vi.fn().mockResolvedValue(jsonResponse({})) as unknown as typeof fetch;
      expect(await listProjects("token", null)).toEqual([]);
    });

    it.each(["not-an-id", 0, -1, Number.MAX_SAFE_INTEGER + 1, {}])("refuses malformed GitHub repository id %s", async (repoId) => {
      global.fetch = vi.fn().mockResolvedValue(jsonResponse({ projects: [{
        id: "p1", name: "site", link: { type: "github", org: "Acme", repo: "Web", repoId },
      }] })) as unknown as typeof fetch;
      expect(await listProjects("token", null)).toEqual([{ id: "p1", name: "site" }]);
    });

    it("throws with the HTTP status on a non-ok response", async () => {
      global.fetch = vi.fn().mockResolvedValue(jsonResponse({}, false, 403)) as unknown as typeof fetch;
      await expect(listProjects("token", null)).rejects.toThrow("Vercel list projects HTTP 403");
    });
  });

  describe("listProjectEnv", () => {
    it("requests decrypt=true and the encoded project id, with teamId appended", async () => {
      const fetchMock = vi.fn().mockResolvedValue(jsonResponse({ envs: [] }));
      global.fetch = fetchMock as unknown as typeof fetch;
      await listProjectEnv("token", "my project/id", "team_1");
      expect(fetchMock.mock.calls[0][0]).toBe(
        "https://api.vercel.com/v9/projects/my%20project%2Fid/env?decrypt=true&teamId=team_1"
      );
    });

    it("maps env vars including null values for sensitive-typed vars", async () => {
      global.fetch = vi.fn().mockResolvedValue(
        jsonResponse({ envs: [{ key: "A", value: "v1", target: ["production"], type: "encrypted" },
                                { key: "B", type: "sensitive" }] })
      ) as unknown as typeof fetch;
      const envs = await listProjectEnv("token", "proj", null);
      expect(envs).toEqual([
        { key: "A", value: "v1", target: ["production"], type: "encrypted" },
        { key: "B", value: null, target: undefined, type: "sensitive" },
      ]);
    });

    it("throws with the HTTP status on a non-ok response", async () => {
      global.fetch = vi.fn().mockResolvedValue(jsonResponse({}, false, 404)) as unknown as typeof fetch;
      await expect(listProjectEnv("token", "proj", null)).rejects.toThrow("Vercel env read HTTP 404");
    });
  });
});
