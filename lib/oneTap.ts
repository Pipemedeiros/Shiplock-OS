/**
 * Google One Tap (Felipe 2026-09-30): the corner prompt that signs a visitor
 * in with the Google account already in the browser. The client id is the
 * public web client the Supabase Google provider already uses (it appears in
 * every sign-in redirect); NEXT_PUBLIC_GOOGLE_CLIENT_ID overrides it.
 */
export const GOOGLE_CLIENT_ID = process.env.NEXT_PUBLIC_GOOGLE_CLIENT_ID
  ?? "1029881902535-oodidpe3pimrmdksh04bgsr05c3sfbmr.apps.googleusercontent.com";

/**
 * A fresh nonce per prompt: Google receives the SHA-256 hex and puts it in the
 * ID token; Supabase receives the raw value and checks they match, so a
 * captured token cannot be replayed into another sign-in.
 */
export async function makeNonce(): Promise<[raw: string, hashed: string]> {
  const raw = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32))));
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(raw));
  const hashed = Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, "0")).join("");
  return [raw, hashed];
}
