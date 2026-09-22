import { toNextJsHandler } from "better-auth/next-js";
import { getBetterAuth, isBetterAuthConfigured } from "@/lib/betterAuth";

// Better Auth handler for the 2FA layer ONLY (base path /api/2fa). Gated: until
// BETTER_AUTH_SECRET + DATABASE_URL are set, this returns 501 and instantiates
// nothing — the app is untouched. Supabase Auth still owns login + the session
// + RLS; this endpoint only manages the TOTP factor. See AGENTS.md.
function notConfigured() {
  return new Response(JSON.stringify({ error: "2FA is not configured." }), {
    status: 501,
    headers: { "content-type": "application/json" },
  });
}

export async function GET(req: Request) {
  if (!isBetterAuthConfigured()) return notConfigured();
  return toNextJsHandler(getBetterAuth()).GET(req);
}

export async function POST(req: Request) {
  if (!isBetterAuthConfigured()) return notConfigured();
  return toNextJsHandler(getBetterAuth()).POST(req);
}
