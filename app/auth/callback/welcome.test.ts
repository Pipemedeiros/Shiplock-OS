import { beforeEach, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";

// A successful sign-in schedules the welcome email after the response;
// a failed exchange schedules nothing.
const state = vi.hoisted(() => ({ exchange: vi.fn(), welcome: vi.fn(), after: vi.fn() }));
vi.mock("next/server", async (orig) => ({ ...(await orig<typeof import("next/server")>()), after: state.after }));
vi.mock("@/lib/supabaseServer", () => ({ getSupabaseServer: async () => ({ auth: { exchangeCodeForSession: state.exchange } }) }));
vi.mock("@/lib/welcomeEmail", () => ({ sendWelcomeOnce: state.welcome }));
const { GET } = await import("./route");
const call = () => GET(new NextRequest("https://shiplock.dev/auth/callback?code=abc&next=/onboarding"));

beforeEach(() => { vi.clearAllMocks(); state.welcome.mockResolvedValue(true); });

it("schedules the welcome email for the signed-in user after responding", async () => {
  const user = { id: "u1", email: "a@b.co" };
  state.exchange.mockResolvedValue({ data: { user }, error: null });
  await call();
  expect(state.after).toHaveBeenCalledTimes(1);
  await state.after.mock.calls[0][0]();
  expect(state.welcome).toHaveBeenCalledWith(user, "https://shiplock.dev");
});

it("schedules nothing when the code exchange fails", async () => {
  state.exchange.mockResolvedValue({ data: { user: null }, error: { message: "bad code" } });
  await call();
  expect(state.after).not.toHaveBeenCalled();
});
