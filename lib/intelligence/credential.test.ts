import { readFileSync } from "node:fs";
import { beforeEach, describe, expect, it, vi } from "vitest";

const state = vi.hoisted(() => ({ maybeSingle: vi.fn(), del: vi.fn() }));
vi.mock("@/lib/supabase", () => ({ getSupabaseAdmin: () => ({ from: () => ({
  select: () => ({ eq: () => ({ maybeSingle: state.maybeSingle }) }),
  delete: () => ({ eq: state.del }),
}) }) }));

import * as credential from "./credential";

beforeEach(() => { vi.clearAllMocks(); state.del.mockResolvedValue({ error: null }); });

// The customer API-key mode is retired (Felipe, 2026-10-01). A key saved before
// then can be seen by its last 4 characters and erased; it is never saved,
// decrypted or used again.
describe("a stored customer API key, after retirement", () => {
  it("can no longer be saved or loaded", () => {
    expect(Object.keys(credential).sort()).toEqual(["getApiKeyStatus", "removeApiKey"]);
    expect(readFileSync("lib/intelligence/credential.ts", "utf8")).not.toMatch(/@\/lib\/crypto|key_encrypted/);
  });

  it("reports status by hint only", async () => {
    state.maybeSingle.mockResolvedValue({ data: { key_hint: "wxYz", created_at: "2026-09-23T00:00:00Z" }, error: null });
    const status = await credential.getApiKeyStatus("u1");
    expect(status).toEqual({ stored: true, hint: "wxYz", savedAt: "2026-09-23T00:00:00Z" });
    state.maybeSingle.mockResolvedValue({ data: null, error: null });
    expect(await credential.getApiKeyStatus("u1")).toEqual({ stored: false });
    state.maybeSingle.mockResolvedValue({ data: null, error: { message: "down" } });
    await expect(credential.getApiKeyStatus("u1")).rejects.toThrow();
  });

  it("removes the key", async () => {
    await credential.removeApiKey("u1");
    expect(state.del).toHaveBeenCalledWith("user_id", "u1");
  });
});
