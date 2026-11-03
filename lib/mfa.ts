import { getSupabaseAdmin } from "@/lib/supabase";

/**
 * Two-step sign-in (Supabase MFA, TOTP). A user with a verified authenticator
 * must reach assurance level aal2 before ShipLock serves anything.
 *
 * The factor list ALWAYS comes from Supabase's auth server (admin API, or a
 * getUser response): the session cookie's copy of the user is editable by
 * the browser, so trusting it would let a stolen password drop the factor
 * and skip the code. The aal level is read from a token that was already
 * verified (getClaims, or getUser on the same token). An unreadable factor
 * list fails closed.
 */
type MfaDecision = "ok" | "step_up" | "unknown";
type Factor = { status: string };

/** Whether a session may proceed: ok at aal2 or with no verified factor, step
 * up otherwise, unknown when factors were unreadable. */
export function mfaDecision(aal: unknown, factors: readonly Factor[] | null): MfaDecision {
  if (aal === "aal2") return "ok";
  if (factors === null) return "unknown";
  return factors.some((f) => f.status === "verified") ? "step_up" : "ok";
}

/** For a session at `aal`, whether this user may proceed. One auth server
 * call, only when the session is not already at aal2. */
export async function checkMfa(userId: string, aal: unknown): Promise<MfaDecision> {
  if (aal === "aal2") return "ok";
  try {
    const { data, error } = await getSupabaseAdmin().auth.admin.mfa.listFactors({ userId });
    return mfaDecision(aal, error || !data ? null : data.factors);
  } catch {
    return "unknown";
  }
}

/** The aal claim of an access token. Call only AFTER the token was verified
 * (admin.auth.getUser(token) succeeded): this decodes, it does not verify. */
export function tokenAal(jwt: string): string | undefined {
  const payload = jwt.split(".")[1];
  if (!payload) return undefined;
  try {
    const aal = (JSON.parse(Buffer.from(payload, "base64url").toString("utf8")) as { aal?: unknown }).aal;
    return typeof aal === "string" ? aal : undefined;
  } catch {
    return undefined;
  }
}

/** For a route that verified a bearer access token with
 * admin.auth.getUser(token): the auth server's factors for that user, and
 * that same token's level. */
export function bearerMfaOk(user: { factors?: readonly Factor[] | null }, token: string): boolean {
  return mfaDecision(tokenAal(token), user.factors ?? []) === "ok";
}
