import { beforeEach, describe, expect, it, vi } from "vitest";

const state = vi.hoisted(() => ({ upsert: vi.fn(), maybeSingle: vi.fn(), del: vi.fn() }));
vi.mock("@/lib/crypto", () => ({ encrypt: (s: string) => `enc(${s})`, decrypt: (s: string) => s.replace(/^enc\((.*)\)$/, "$1") }));
vi.mock("@/lib/supabase", () => ({ getSupabaseAdmin: () => ({ from: () => ({
  upsert: state.upsert,
  select: () => ({ eq: () => ({ maybeSingle: state.maybeSingle }) }),
  delete: () => ({ eq: state.del }),
}) }) }));

import { ApiKeyInput, getApiKeyStatus, loadApiKey, removeApiKey, saveApiKey } from "./credential";

const key = "sk-ant-api03-" + "A".repeat(80) + "wxYz";
beforeEach(() => { vi.clearAllMocks(); state.upsert.mockResolvedValue({ error: null }); state.del.mockResolvedValue({ error: null }); });

describe("customer API key storage (10B-2e)", () => {
  it("accepts only an Anthropic key shape, bounded", () => {
    expect(ApiKeyInput.parse({ apiKey: key })).toEqual({ apiKey: key });
    expect(() => ApiKeyInput.parse({ apiKey: "sk-proj-abc" })).toThrow();
    expect(() => ApiKeyInput.parse({ apiKey: key + " " })).toThrow();
    expect(() => ApiKeyInput.parse({ apiKey: "sk-ant-" + "a".repeat(500) })).toThrow();
  });

  it("stores ciphertext, a 4-character hint, and a fresh epoch; never the plaintext", async () => {
    expect(await saveApiKey("u1", key)).toEqual({ stored: true, hint: "wxYz" });
    const [row] = state.upsert.mock.calls[0];
    expect(row).toMatchObject({ user_id: "u1", provider: "anthropic", key_encrypted: `enc(${key})`, key_hint: "wxYz" });
    expect(row.epoch).toMatch(/^[a-f0-9]{64}$/);
    expect(JSON.stringify(row)).not.toContain(`"${key}"`);
    await saveApiKey("u1", key);
    expect(state.upsert.mock.calls[1][0].epoch).not.toBe(row.epoch);
    state.upsert.mockResolvedValue({ error: { message: "down" } });
    await expect(saveApiKey("u1", key)).rejects.toThrow("credential_unwritable");
  });

  it("reports status by hint only, and loads the key server-side for the worker", async () => {
    state.maybeSingle.mockResolvedValue({ data: { key_encrypted: `enc(${key})`, key_hint: "wxYz", epoch: "e".repeat(64), created_at: "2026-09-23T00:00:00Z" }, error: null });
    const status = await getApiKeyStatus("u1");
    expect(status).toEqual({ stored: true, hint: "wxYz", savedAt: "2026-09-23T00:00:00Z" });
    expect(JSON.stringify(status)).not.toContain("sk-ant");
    expect(await loadApiKey("u1")).toEqual({ apiKey: key, epoch: "e".repeat(64) });
    state.maybeSingle.mockResolvedValue({ data: null, error: null });
    expect(await getApiKeyStatus("u1")).toEqual({ stored: false });
    expect(await loadApiKey("u1")).toBeNull();
    state.maybeSingle.mockResolvedValue({ data: null, error: { message: "down" } });
    await expect(getApiKeyStatus("u1")).rejects.toThrow();
    await expect(loadApiKey("u1")).rejects.toThrow();
  });

  it("removes the key", async () => {
    await removeApiKey("u1");
    expect(state.del).toHaveBeenCalledWith("user_id", "u1");
  });
});
