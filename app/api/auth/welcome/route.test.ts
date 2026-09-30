import { beforeEach, expect, it, vi } from "vitest";

const state = vi.hoisted(() => ({ getUser: vi.fn(), welcome: vi.fn() }));
vi.mock("@/lib/supabaseServer", () => ({ getSupabaseServer: async () => ({ auth: { getUser: state.getUser } }) }));
vi.mock("@/lib/welcomeEmail", () => ({ sendWelcomeOnce: state.welcome }));
const { POST } = await import("./route");
const post = () => POST(new Request("https://shiplock.dev/api/auth/welcome", { method: "POST", headers: { origin: "https://shiplock.dev" } }));

beforeEach(() => { vi.clearAllMocks(); state.welcome.mockResolvedValue(true); });

it("sends the welcome email for the signed-in user only", async () => {
  state.getUser.mockResolvedValue({ data: { user: { id: "u1", email: "a@b.co" } } });
  expect(await (await post()).json()).toEqual({ sent: true });
  expect(state.welcome).toHaveBeenCalledWith({ id: "u1", email: "a@b.co" }, expect.any(String));
});

it("refuses without a session and sends nothing", async () => {
  state.getUser.mockResolvedValue({ data: { user: null } });
  expect((await post()).status).toBe(401);
  expect(state.welcome).not.toHaveBeenCalled();
});
