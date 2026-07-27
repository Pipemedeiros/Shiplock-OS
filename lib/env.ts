import { z } from "zod";

// Optional secret that treats an empty string as "unset" — env files and
// hosting UIs commonly leave a key present but blank, and a bare
// `.min(1).optional()` would (wrongly) reject "" instead of ignoring it.
const optionalSecret = z.preprocess((v) => (v === "" ? undefined : v), z.string().min(1).optional());

const envSchema = z.object({
  NEXT_PUBLIC_SUPABASE_URL: z.string().url(),
  NEXT_PUBLIC_SUPABASE_ANON_KEY: z.string().min(1),
  SUPABASE_SERVICE_ROLE_KEY: z.string().min(1),
  STRIPE_SECRET_KEY: z.string().min(1),
  STRIPE_WEBHOOK_SECRET: z.string().min(1),
  STRIPE_PRICE_ID: z.string().min(1),
  RESEND_API_KEY: z.string().min(1),
  RESEND_FROM_EMAIL: z.string().email(),
  NEXT_PUBLIC_APP_URL: z.string().url(),
  ENCRYPTION_KEY: z.string().min(32),
  CRON_SECRET: z.string().min(1),
  ANTHROPIC_API_KEY: z.string().min(1),
  // Optional: the Vercel Integration (OAuth) may not be registered yet.
  // lib/deep/vercel.ts throws a clear error at call time if these are unset —
  // they must stay optional here so app startup isn't blocked on them.
  VERCEL_CLIENT_ID: optionalSecret,
  VERCEL_CLIENT_SECRET: optionalSecret,
  // Optional: the Supabase OAuth app (read-only Management API access, which
  // powers the RLS policy detector) may not be registered yet. The UI hides
  // the connection entirely until both are set — see
  // lib/deep/supabaseMgmt.ts's isSupabaseMgmtConfigured().
  SUPABASE_OAUTH_CLIENT_ID: optionalSecret,
  SUPABASE_OAUTH_CLIENT_SECRET: optionalSecret,
  // Optional: the GitHub App (source scanning) may not be registered yet.
  // lib/deep/github.ts throws a clear error at call time if these are unset.
  // See ROADMAP.md for how to create the App and obtain these.
  GITHUB_APP_ID: optionalSecret,
  GITHUB_APP_PRIVATE_KEY: optionalSecret,
  GITHUB_APP_CLIENT_ID: optionalSecret,
  GITHUB_APP_CLIENT_SECRET: optionalSecret,
  GITHUB_APP_SLUG: optionalSecret,
  GITHUB_WEBHOOK_SECRET: optionalSecret,
  // Optional: Better Auth 2FA (layered on Supabase Auth). lib/betterAuth.ts is
  // only instantiated when BOTH are present. DATABASE_URL is a direct Postgres
  // connection (Supabase) used only by the 2FA layer. See ROADMAP.md.
  BETTER_AUTH_SECRET: optionalSecret,
  DATABASE_URL: optionalSecret,
});

export const env = envSchema.parse(process.env);
export type Env = z.infer<typeof envSchema>;
