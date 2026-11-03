import { beforeEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";

// A Supabase Management connect mints a new epoch; disconnect clears it.
const mocks = vi.hoisted(() => ({ pro: vi.fn(), exchange: vi.fn(), update: vi.fn() }));
vi.mock("@/lib/deep/proGate", () => ({ requireProUser: mocks.pro }));
vi.mock("@/lib/crypto", () => ({ encrypt: (v: string) => `enc(${v})` }));
vi.mock("@/lib/deep/supabaseMgmt", () => ({ exchangeCodeForToken: mocks.exchange, listProjects: async () => [{ ref: "ref1" }] }));
vi.mock("next/headers", () => ({ cookies: async () => ({ get: () => ({ value: "state-1" }), delete: () => {} }) }));
vi.mock("@/lib/supabase", () => ({ getSupabaseAdmin: () => ({ from: () => {
  const chain = {
    select: () => chain, is: () => chain,
    eq: () => chain,
    maybeSingle: async () => ({ data: { monitored_project_url: "https://ref1.supabase.co" } }),
    then: (resolve: (v: unknown) => unknown) => Promise.resolve({ error: null }).then(resolve),
  };
  return { ...chain, update: (payload: unknown) => { mocks.update(payload); return chain; } };
} }) }));

import { GET } from "./callback/route";
import { POST } from "./disconnect/route";

beforeEach(() => {
  vi.clearAllMocks();
  mocks.pro.mockResolvedValue({ userId: "u1" });
  mocks.exchange.mockResolvedValue({ accessToken: "a", refreshToken: "r", expiresAt: null });
});

describe("Supabase Management connection epoch", () => {
  it("mints a fresh epoch on each connect", async () => {
    const call = () => GET(new NextRequest("https://shiplock.dev/api/deep/supabase/callback?code=c&state=state-1"));
    await call();
    await call();
    const epochs = mocks.update.mock.calls.map(([p]) => (p as Record<string, string>).supabase_mgmt_connection_epoch);
    expect(epochs).toHaveLength(2);
    expect(epochs[0]).toMatch(/^[a-f0-9]{64}$/);
    expect(epochs[0]).not.toBe(epochs[1]);
  });

  it("clears the epoch on disconnect", async () => {
    await POST(new Request("https://shiplock.dev/api/deep/supabase/disconnect", { method: "POST", headers: { origin: "https://shiplock.dev" } }));
    expect(mocks.update).toHaveBeenCalledWith(expect.objectContaining({
      supabase_mgmt_token_encrypted: null, supabase_mgmt_connection_epoch: null,
    }));
  });
});
