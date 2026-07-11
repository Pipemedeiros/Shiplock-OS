// Supabase project URLs follow: https://<project-ref>.supabase.co
const SUPABASE_URL_RE = /^https:\/\/[a-z0-9-]+\.supabase\.co$/;

// Legacy Supabase anon keys are JWT tokens — always start with "eyJ"
// (base64 '{"'). Newer projects issue the current key model instead:
// sb_publishable_... (anon-equivalent, safe to submit) and
// sb_secret_... (service_role-equivalent — dangerous, same as a legacy
// service_role JWT). Both accepted at this layer so a customer on the
// new format isn't hard-rejected before a scan can even run; analyzeKey()
// in lib/scanner.ts is what actually treats sb_secret_ as a CRITICAL
// finding, the same way it already does for a service_role JWT.
const ANON_KEY_PREFIX = "eyJ";
const PUBLISHABLE_KEY_PREFIX = "sb_publishable_";
const SECRET_KEY_PREFIX = "sb_secret_";

export class ValidationError extends Error {
  constructor(
    message: string,
    public readonly field: string
  ) {
    super(message);
    this.name = "ValidationError";
  }
}

/** Removes all HTML/XML tags from a string. */
export function stripHtml(input: string): string {
  return input.replace(/<[^>]*>/g, "").trim();
}

/** Strips HTML and returns a clean, trimmed string. Throws if the result is empty. */
export function sanitizeInput(input: unknown, field: string): string {
  if (typeof input !== "string") {
    throw new ValidationError(`${field} must be a string.`, field);
  }
  const cleaned = stripHtml(input);
  if (cleaned.length === 0) {
    throw new ValidationError(`${field} must not be empty.`, field);
  }
  return cleaned;
}

/** Validates that a value is a well-formed Supabase project URL. */
export function validateSupabaseUrl(value: unknown): string {
  const url = sanitizeInput(value, "supabaseUrl");
  if (!SUPABASE_URL_RE.test(url)) {
    throw new ValidationError(
      "supabaseUrl must match https://<project-ref>.supabase.co",
      "supabaseUrl"
    );
  }
  return url;
}

/** Validates that a value looks like a Supabase anon key — either the
 * legacy JWT format or the current sb_publishable_/sb_secret_ format.
 * Deliberately does NOT reject sb_secret_ here: the whole point of
 * check 2 (key type detection) is to flag a submitted service-role-
 * equivalent key as a CRITICAL finding, same as a service_role JWT
 * already is — rejecting it at input validation would silently hide
 * that exact finding instead of reporting it. */
export function validateAnonKey(value: unknown): string {
  const key = sanitizeInput(value, "anonKey");
  const looksValid =
    key.startsWith(ANON_KEY_PREFIX) ||
    key.startsWith(PUBLISHABLE_KEY_PREFIX) ||
    key.startsWith(SECRET_KEY_PREFIX);
  if (!looksValid) {
    throw new ValidationError(
      'anonKey must be a Supabase key — either a JWT starting with "eyJ", or the newer "sb_publishable_..." format.',
      "anonKey"
    );
  }
  return key;
}

const APP_URL_MAX_LENGTH = 2048;

/** Validates the optional "your app's live URL" input (lib.scanner.ts's
 * slop-squatting and secrets-exposure checks run against this instead of
 * the Supabase project URL when it's provided — see scanProject()). Any
 * well-formed https:// URL, not just *.supabase.co — this is the
 * customer's own frontend, which can be hosted anywhere. */
export function validateAppUrl(value: unknown): string {
  const url = sanitizeInput(value, "appUrl");
  if (url.length > APP_URL_MAX_LENGTH) {
    throw new ValidationError("appUrl is too long.", "appUrl");
  }
  if (!url.startsWith("https://")) {
    throw new ValidationError("appUrl must start with https://", "appUrl");
  }
  try {
    new URL(url);
  } catch {
    throw new ValidationError("appUrl must be a valid URL.", "appUrl");
  }
  return url;
}

