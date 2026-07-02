import { NextRequest, NextResponse } from "next/server";
import { getSupabaseServer } from "@/lib/supabaseServer";

// OAuth (and email-link) callback. Supabase Auth handles the state
// parameter itself as part of the PKCE flow — this route only exchanges
// the authorization code for a session; it never sees or validates state
// directly, that happens inside exchangeCodeForSession() against the
// code_verifier stored in the PKCE cookie set when the flow started.
export async function GET(req: NextRequest) {
  const { searchParams, origin } = new URL(req.url);
  const code = searchParams.get("code");
  const next = searchParams.get("next") ?? "/onboarding";

  if (code) {
    const supabase = await getSupabaseServer();
    const { error } = await supabase.auth.exchangeCodeForSession(code);
    if (!error) {
      return NextResponse.redirect(`${origin}${next}`);
    }
    console.error("[auth/callback] exchangeCodeForSession error:", error.message);
  }

  return NextResponse.redirect(`${origin}/auth?error=oauth_failed`);
}
