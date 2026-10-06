import { beforeEach, describe, expect, it, vi } from "vitest";

const getClaims = vi.fn();
vi.mock("@/lib/supabaseServer", () => ({ getSupabaseServer: async () => ({ auth: { getClaims } }) }));
vi.mock("next/navigation", () => ({ redirect: (to: string) => { throw new Error(`redirect:${to}`); } }));
vi.mock("@/components/v3/TwoStep", () => ({ MfaChallenge: () => null }));
const { default: MfaPage } = await import("./page");
const open = (next?: string) => MfaPage({ searchParams: Promise.resolve(next ? { next } : {}) });

describe("code step page", () => {
  beforeEach(() => getClaims.mockReset());
  it("sends a visitor with no session to sign in", async () => {
    getClaims.mockResolvedValue({ data: null, error: new Error("no session") });
    await expect(open()).rejects.toThrow("redirect:/auth");
  });
  it("lets a session that already passed the code continue, only to a safe path", async () => {
    getClaims.mockResolvedValue({ data: { claims: { sub: "u", aal: "aal2" } }, error: null });
    await expect(open("/dashboard/settings")).rejects.toThrow("redirect:/dashboard/settings");
    await expect(open("https://evil.example")).rejects.toThrow("redirect:/dashboard");
  });
  it("asks an aal1 session for its code", async () => {
    getClaims.mockResolvedValue({ data: { claims: { sub: "u", aal: "aal1" } }, error: null });
    await expect(open()).resolves.toBeTruthy();
  });
});
