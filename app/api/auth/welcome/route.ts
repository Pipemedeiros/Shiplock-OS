import { NextResponse } from "next/server";
import { crossSiteRefusal } from "@/lib/security/sameOrigin";
import { getSupabaseServer } from "@/lib/supabaseServer";
import { sendWelcomeOnce } from "@/lib/welcomeEmail";

// One Tap signs in on the page, not through /auth/callback, so the page asks
// for the welcome email here. The user comes from the session cookie, never
// the body; sendWelcomeOnce sends at most once per new account.
export async function POST(request: Request) {
  const refused = crossSiteRefusal(request);
  if (refused) return refused;
  const { data } = await (await getSupabaseServer()).auth.getUser();
  if (!data.user) return NextResponse.json({ error: "Sign in first." }, { status: 401 });
  const sent = await sendWelcomeOnce(data.user, process.env.NEXT_PUBLIC_APP_URL ?? new URL(request.url).origin).catch(() => false);
  return NextResponse.json({ sent });
}
