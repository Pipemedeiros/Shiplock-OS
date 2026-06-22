// Supabase project URLs follow: https://<project-ref>.supabase.co
const SUPABASE_URL_RE = /^https:\/\/[a-z0-9-]+\.supabase\.co$/;

// Supabase anon keys are JWT tokens — always start with "eyJ" (base64 '{"')
const ANON_KEY_PREFIX = "eyJ";

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

/** Validates that a value looks like a Supabase anon JWT key. */
export function validateAnonKey(value: unknown): string {
  const key = sanitizeInput(value, "anonKey");
  if (!key.startsWith(ANON_KEY_PREFIX)) {
    throw new ValidationError(
      'anonKey must be a JWT token starting with "eyJ".',
      "anonKey"
    );
  }
  return key;
}

