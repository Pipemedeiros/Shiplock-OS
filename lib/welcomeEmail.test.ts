import { beforeEach, describe, expect, it, vi } from "vitest";

// Q29: one welcome email per new account, with the logo, marked on the auth
// user before sending so a repeated sign-in can never send it twice.
const state = vi.hoisted(() => ({ send: vi.fn(), update: vi.fn() }));
vi.mock("@/lib/email", () => ({ sendEmail: state.send }));
vi.mock("@/lib/supabase", () => ({ getSupabaseAdmin: () => ({ auth: { admin: { updateUserById: state.update } } }) }));
import { sendWelcomeOnce, welcomeMessage } from "./welcomeEmail";

const now = new Date("2026-09-30T12:00:00Z");
const user = (over: object = {}) => ({ id: "u1", email: "founder@example.com", created_at: "2026-09-30T11:58:00Z", app_metadata: { provider: "github" }, ...over });

beforeEach(() => { state.send.mockReset().mockResolvedValue(true); state.update.mockReset().mockResolvedValue({ error: null }); });

describe("welcome email", () => {
  it("says what happens next in plain words, with the logo and a text version, and no dashes", () => {
    const m = welcomeMessage("https://shiplock.dev");
    expect(m.subject).toBe("Welcome to ShipLock");
    expect(m.html).toContain('src="https://shiplock.dev/apple-icon.png"');
    expect(m.html).toContain('href="https://shiplock.dev/onboarding"');
    expect(m.text).toMatch(/GitHub/);
    expect(`${m.subject} ${m.text} ${m.html.replace(/<[^>]+>/g, " ")}`).not.toMatch(/[–—]/);
  });

  it("marks the account, then sends once, to a new account only", async () => {
    expect(await sendWelcomeOnce(user(), "https://shiplock.dev", now)).toBe(true);
    expect(state.update).toHaveBeenCalledWith("u1", { app_metadata: { provider: "github", welcome_sent_at: now.toISOString() } });
    expect(state.update.mock.invocationCallOrder[0]).toBeLessThan(state.send.mock.invocationCallOrder[0]);
    expect(state.send).toHaveBeenCalledWith(expect.objectContaining({ to: "founder@example.com", html: expect.any(String) }), "welcome");
  });

  it("never sends twice, to an older account, without an address, or when marking failed", async () => {
    expect(await sendWelcomeOnce(user({ app_metadata: { welcome_sent_at: "x" } }), "https://shiplock.dev", now)).toBe(false);
    expect(await sendWelcomeOnce(user({ created_at: "2026-09-01T00:00:00Z" }), "https://shiplock.dev", now)).toBe(false);
    expect(await sendWelcomeOnce(user({ email: undefined }), "https://shiplock.dev", now)).toBe(false);
    state.update.mockResolvedValue({ error: { message: "nope" } });
    expect(await sendWelcomeOnce(user(), "https://shiplock.dev", now)).toBe(false);
    expect(state.send).not.toHaveBeenCalled();
  });
});
