import { createHash, randomBytes } from "crypto";
import { getSupabaseAdmin } from "@/lib/supabase";

// ShipLock personal access tokens (PATs) for the MCP integration. Only the
// SHA-256 hash is stored; the raw token is shown once. resolveApiToken maps a
// presented PAT to a paid user_id (or null), and is the auth path for the
// /api/mcp/* routes the MCP server calls.

const PREFIX = "shiplock_pat_";

export function hashToken(raw: string): string {
  return createHash("sha256").update(raw).digest("hex");
}

// Returns the raw token (show once) + its hash (store this).
export function generateToken(): { raw: string; hash: string } {
  const raw = PREFIX + randomBytes(24).toString("base64url");
  return { raw, hash: hashToken(raw) };
}

export function isTokenShaped(raw: string): boolean {
  return raw.startsWith(PREFIX) && raw.length > PREFIX.length + 20;
}

export interface ResolvedToken {
  userId: string;
  isPaid: boolean;
}

// Look up a presented PAT → user (checking not-revoked). Also verifies the user
// is currently paid (MCP is a paid feature). Best-effort updates last_used_at.
// Returns null for any invalid/revoked/unpaid token — callers 401/402 generically.
export async function resolveApiToken(raw: string): Promise<ResolvedToken | null> {
  if (!raw || !isTokenShaped(raw)) return null;
  const admin = getSupabaseAdmin();

  const { data: row } = await admin
    .from("api_tokens")
    .select("id, user_id, revoked_at")
    .eq("token_hash", hashToken(raw))
    .maybeSingle();
  if (!row || row.revoked_at) return null;

  const { data: profile } = await admin
    .from("user_profiles")
    .select("is_paid")
    .eq("id", row.user_id)
    .maybeSingle();

  // Fire-and-forget last-used stamp (non-critical).
  void admin.from("api_tokens").update({ last_used_at: new Date().toISOString() }).eq("id", row.id);

  return { userId: row.user_id as string, isPaid: Boolean(profile?.is_paid) };
}
