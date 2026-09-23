import { randomBytes } from "node:crypto";
import { z } from "zod";
import { encrypt, decrypt } from "@/lib/crypto";
import { getSupabaseAdmin } from "@/lib/supabase";

/** The customer's own model key for API-key intelligence mode (10B-2e,
 * migration 079). Stored only as ciphertext, never returned after write, never
 * put in a job. The worker loads it at call time; ShipLock never substitutes
 * its own key. */
export const ApiKeyInput = z.strictObject({ apiKey: z.string().regex(/^sk-ant-[A-Za-z0-9_-]{20,300}$/) });

export type ApiKeyStatus = { stored: false } | { stored: true; hint: string; savedAt: string };

const row = z.object({ key_encrypted: z.string(), key_hint: z.string(), epoch: z.string().regex(/^[a-f0-9]{64}$/), created_at: z.string() });

async function read(userId: string) {
  const { data, error } = await getSupabaseAdmin().from("intelligence_credentials")
    .select("key_encrypted, key_hint, epoch, created_at").eq("user_id", userId).maybeSingle();
  if (error) throw new Error("credential_unreadable");
  return data ? row.parse(data) : null;
}

export async function saveApiKey(userId: string, apiKey: string): Promise<{ stored: true; hint: string }> {
  const { apiKey: key } = ApiKeyInput.parse({ apiKey });
  const hint = key.slice(-4);
  const { error } = await getSupabaseAdmin().from("intelligence_credentials").upsert({
    user_id: userId, provider: "anthropic", key_encrypted: encrypt(key), key_hint: hint,
    // A new epoch on every save: work done under a replaced key is traceable.
    epoch: randomBytes(32).toString("hex"), created_at: new Date().toISOString(),
  }, { onConflict: "user_id" });
  if (error) throw new Error("credential_unwritable");
  return { stored: true, hint };
}

export async function getApiKeyStatus(userId: string): Promise<ApiKeyStatus> {
  const r = await read(userId);
  return r ? { stored: true, hint: r.key_hint, savedAt: r.created_at } : { stored: false };
}

/** Server-only: the plaintext key and its epoch, for the API-mode worker. */
export async function loadApiKey(userId: string): Promise<{ apiKey: string; epoch: string } | null> {
  const r = await read(userId);
  return r ? { apiKey: decrypt(r.key_encrypted), epoch: r.epoch } : null;
}

export async function removeApiKey(userId: string): Promise<void> {
  const { error } = await getSupabaseAdmin().from("intelligence_credentials").delete().eq("user_id", userId);
  if (error) throw new Error("credential_unwritable");
}
