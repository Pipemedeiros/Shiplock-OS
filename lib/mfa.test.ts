import { describe, expect, it, vi } from "vitest";

// Supabase MFA (Felipe 2026-10-06: make sign-in safe). A user with a verified
// authenticator must reach aal2 before ShipLock serves anything; the factor
// list always comes from Supabase's auth server, never the editable session
// cookie, and an unreadable list fails closed.
const s = vi.hoisted(() => ({ listFactors: vi.fn() }));
vi.mock("@/lib/supabase", () => ({ getSupabaseAdmin: () => ({ auth: { admin: { mfa: { listFactors: s.listFactors } } } }) }));
const { mfaDecision, checkMfa, tokenAal, bearerMfaOk } = await import("./mfa");

const verified = { id: "f1", status: "verified", factor_type: "totp" };
const unverified = { id: "f2", status: "unverified", factor_type: "totp" };

describe("mfa decision", () => {
  it("lets a user without a verified factor through at aal1", () => {
    expect(mfaDecision("aal1", [])).toBe("ok");
    expect(mfaDecision("aal1", [unverified])).toBe("ok");
  });
  it("asks a user with a verified factor to step up until aal2", () => {
    expect(mfaDecision("aal1", [verified])).toBe("step_up");
    expect(mfaDecision(undefined, [verified])).toBe("step_up");
    expect(mfaDecision("aal2", [verified])).toBe("ok");
  });
  it("fails closed when the factors could not be read", () => {
    expect(mfaDecision("aal1", null)).toBe("unknown");
  });
});

describe("checkMfa", () => {
  it("does not call the auth server for a session already at aal2", async () => {
    const before = s.listFactors.mock.calls.length;
    expect(await checkMfa("u1", "aal2")).toBe("ok");
    expect(s.listFactors.mock.calls.length).toBe(before);
  });
  it("reads the user's factors from the auth server at aal1", async () => {
    s.listFactors.mockResolvedValue({ data: { factors: [verified] }, error: null });
    expect(await checkMfa("u1", "aal1")).toBe("step_up");
    expect(s.listFactors).toHaveBeenCalledWith({ userId: "u1" });
  });
  it("fails closed on an auth server error", async () => {
    s.listFactors.mockResolvedValue({ data: null, error: { message: "down" } });
    expect(await checkMfa("u1", "aal1")).toBe("unknown");
  });
  it("fails closed when the call throws", async () => {
    s.listFactors.mockImplementation(() => { throw new Error("network"); });
    expect(await checkMfa("u1", "aal1")).toBe("unknown");
  });
});

describe("tokenAal", () => {
  const jwt = (payload: object) => `h.${Buffer.from(JSON.stringify(payload)).toString("base64url")}.s`;
  it("reads aal from a token's payload", () => {
    expect(tokenAal(jwt({ sub: "u", aal: "aal2" }))).toBe("aal2");
  });
  it("returns undefined for a malformed token", () => {
    expect(tokenAal("not-a-jwt")).toBeUndefined();
    expect(tokenAal(jwt({ sub: "u" }))).toBeUndefined();
  });
});

describe("bearerMfaOk", () => {
  const jwt = (aal: string) => `h.${Buffer.from(JSON.stringify({ aal })).toString("base64url")}.s`;
  it("uses the auth server's factors with the verified token's level", () => {
    expect(bearerMfaOk({ factors: [verified] }, jwt("aal1"))).toBe(false);
    expect(bearerMfaOk({ factors: [verified] }, jwt("aal2"))).toBe(true);
    expect(bearerMfaOk({}, jwt("aal1"))).toBe(true);
  });
});
