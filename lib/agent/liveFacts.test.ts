import { describe, expect, it, vi, beforeEach } from "vitest";

const loadGraphInput = vi.fn();
vi.mock("@/lib/graph/graphRun", () => ({ loadGraphInput }));

const { loadLiveFacts } = await import("./liveFacts");

describe("loadLiveFacts", () => {
  beforeEach(() => loadGraphInput.mockReset());

  it("returns nothing when no runtime collector has ever run", async () => {
    // Absent is not empty. An account with nothing connected must not look like
    // one whose providers were read and reported clean, which is the rulesRead
    // mistake on a new surface.
    loadGraphInput.mockResolvedValue({ routes: [] });
    expect(await loadLiveFacts("u")).toEqual([]);
  });

  it("returns nothing, without throwing, when a provider was read and had nothing", async () => {
    loadGraphInput.mockResolvedValue({ runtimeProvidersRead: ["vercel"], runtimeEnvVars: [] });
    expect(await loadLiveFacts("u")).toEqual([]);
  });

  it("makes a credential-shaped variable citable, with a stable id", async () => {
    loadGraphInput.mockResolvedValue({
      runtimeProvidersRead: ["vercel"],
      runtimeEnvVars: [{ key: "STRIPE_SECRET_KEY", target: ["production"], provider: "vercel" }],
    });
    const facts = await loadLiveFacts("u");
    expect(facts).toHaveLength(1);
    expect(facts[0].id).toBe("vercel:env:STRIPE_SECRET_KEY");
    expect(facts[0].statement).toContain("production");
  });

  it("ranks a public-prefixed credential first, because it can carry a finding", async () => {
    loadGraphInput.mockResolvedValue({
      runtimeProvidersRead: ["vercel"],
      runtimeEnvVars: [
        { key: "DATABASE_PASSWORD", target: ["production"], provider: "vercel" },
        { key: "NEXT_PUBLIC_SERVICE_ROLE_KEY", target: ["production"], provider: "vercel" },
      ],
    });
    const facts = await loadLiveFacts("u");
    expect(facts[0].id).toBe("vercel:public-secret:NEXT_PUBLIC_SERVICE_ROLE_KEY");
    expect(facts[0].statement).toContain("browser");
  });

  it("never carries a value, only a name and a scope", async () => {
    loadGraphInput.mockResolvedValue({
      runtimeProvidersRead: ["vercel"],
      runtimeEnvVars: [{ key: "API_KEY", target: ["production"], provider: "vercel" }],
    });
    const [fact] = await loadLiveFacts("u");
    expect(fact.statement).not.toMatch(/sk_|secret_value|=/);
  });

  it("ignores an ordinary variable that is not credential shaped", async () => {
    loadGraphInput.mockResolvedValue({
      runtimeProvidersRead: ["vercel"],
      runtimeEnvVars: [{ key: "NEXT_PUBLIC_APP_URL", target: ["production"], provider: "vercel" }],
    });
    expect(await loadLiveFacts("u")).toEqual([]);
  });
});
