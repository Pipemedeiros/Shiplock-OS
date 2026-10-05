import { z } from "zod";
import { getSupabaseAdmin } from "@/lib/supabase";

/** A customer model key saved for the retired API-key mode (10B-2e, migration
 * 079). ShipLock runs no model (Felipe, 2026-10-01), so a stored key is never
 * saved, decrypted or used again: the customer sees its last 4 characters and
 * can erase it. The table is dropped once Felipe approves that migration. */
export type ApiKeyStatus = { stored: false } | { stored: true; hint: string; savedAt: string };

const row = z.object({ key_hint: z.string(), created_at: z.string() });

export async function getApiKeyStatus(userId: string): Promise<ApiKeyStatus> {
  const { data, error } = await getSupabaseAdmin().from("intelligence_credentials")
    .select("key_hint, created_at").eq("user_id", userId).maybeSingle();
  if (error) throw new Error("credential_unreadable");
  if (!data) return { stored: false };
  const r = row.parse(data);
  return { stored: true, hint: r.key_hint, savedAt: r.created_at };
}

export async function removeApiKey(userId: string): Promise<void> {
  const { error } = await getSupabaseAdmin().from("intelligence_credentials").delete().eq("user_id", userId);
  if (error) throw new Error("credential_unwritable");
}
