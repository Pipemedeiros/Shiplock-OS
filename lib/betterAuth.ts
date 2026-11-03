import { betterAuth } from "better-auth";
import { twoFactor } from "better-auth/plugins";
import { Pool } from "pg";

// Better Auth is layered ONLY for TOTP two-factor. Supabase Auth stays the
// identity + JWT + RLS source of truth — every RLS policy is auth.uid(), so
// Better Auth must never own login or issue the app session, or the entire
// data layer breaks. This instance owns nothing but the 2FA factor.
//
// Instantiated LAZILY and only when both env vars are present, so the app
// builds and runs completely untouched until 2FA is deliberately enabled.
// Requires (see AGENTS.md): BETTER_AUTH_SECRET and DATABASE_URL (a direct
// Postgres connection string from Supabase — the app otherwise only uses the
// REST layer, so this is a new, 2FA-only credential).

function createInstance() {
  return betterAuth({
    secret: process.env.BETTER_AUTH_SECRET,
    baseURL: process.env.NEXT_PUBLIC_APP_URL,
    // Dedicated base path — /api/auth/* is already the Supabase OAuth callback,
    // so Better Auth lives under /api/2fa to avoid any collision.
    basePath: "/api/2fa",
    database: new Pool({ connectionString: process.env.DATABASE_URL }),
    // Two-factor only. No emailAndPassword / social here — login stays on
    // Supabase Auth; this instance manages the TOTP factor and nothing else.
    plugins: [twoFactor()],
  });
}

let instance: ReturnType<typeof createInstance> | null = null;

/** Whether the optional Better Auth 2FA layer has its secret and database. */
export function isBetterAuthConfigured(): boolean {
  return Boolean(process.env.BETTER_AUTH_SECRET && process.env.DATABASE_URL);
}

/** The Better Auth instance, created once. Throws when it is not configured. */
export function getBetterAuth() {
  if (!isBetterAuthConfigured()) {
    throw new Error("BETTER_AUTH_SECRET and DATABASE_URL must be set to use 2FA (see AGENTS.md).");
  }
  if (instance) return instance;
  const created = createInstance();
  instance = created;
  return created;
}
