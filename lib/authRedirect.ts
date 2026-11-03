export const AUTH_NEXT_COOKIE = "sl_auth_next";

/** Keep post-auth navigation on this origin; never trust a query or cookie path. */
export function safeNext(raw: string | null | undefined, fallback = "/onboarding"): string {
  if (!raw || raw[0] !== "/") return fallback;
  if (raw.startsWith("//") || raw.includes("\\") || /[\u0000-\u001f\u007f]/.test(raw)) return fallback;

  try {
    const parsed = new URL(raw, "https://shiplock.invalid");
    if (parsed.origin !== "https://shiplock.invalid") return fallback;
    return `${parsed.pathname}${parsed.search}${parsed.hash}`;
  } catch {
    return fallback;
  }
}

/** Encodes a post-sign-in path, keeping only same-site paths. */
export function encodeAuthNext(nextPath: string): string {
  return encodeURIComponent(safeNext(nextPath));
}

/** Decodes a post-sign-in path; anything off-site or malformed is null. */
export function decodeAuthNext(raw: string | null | undefined): string | null {
  if (!raw) return null;
  try {
    return safeNext(decodeURIComponent(raw));
  } catch {
    return null;
  }
}
