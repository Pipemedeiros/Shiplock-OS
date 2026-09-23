import { NextRequest, NextResponse } from "next/server";
import { timingSafeEqual } from "crypto";
import { cookies } from "next/headers";
import { requireProUser } from "@/lib/deep/proGate";
import { getSupabaseAdmin } from "@/lib/supabase";
import { encrypt } from "@/lib/crypto";
import { exchangeCodeForToken, listProjects } from "@/lib/deep/supabaseMgmt";
import { newConnectionEpoch } from "@/lib/deep/providerRepositoryMap";

// Return leg of the read-only Supabase Management connection. Pro-gated
// server-side, so a signed-out or unpaid caller can't land a connection here
// even with a crafted URL. Tokens are stored encrypted; plaintext never touches
// the DB or the logs.
export async function GET(req: NextRequest) {
  const base = process.env.NEXT_PUBLIC_APP_URL ?? "";
  const fail = (why: string) =>
    NextResponse.redirect(`${base}/dashboard/settings?supabase=${why}`, { status: 303 });

  const pro = await requireProUser();
  if (!pro) return fail("forbidden");

  const code = req.nextUrl.searchParams.get("code");
  const state = req.nextUrl.searchParams.get("state");
  if (!code || !state) return fail("error");

  // CSRF: the state must match the nonce we set when the flow started.
  const jar = await cookies();
  const expected = jar.get("sl_sb_state")?.value;
  jar.delete("sl_sb_state");
  if (!expected || expected.length !== state.length) return fail("state");
  if (!timingSafeEqual(Buffer.from(expected), Buffer.from(state))) return fail("state");

  try {
    const token = await exchangeCodeForToken(code, base);

    // Scope the connection to the project we already monitor, so it can never
    // be pointed at a different one. If we can't match it, we still store the
    // connection but leave the ref null and let the customer pick later.
    const admin = getSupabaseAdmin();
    const { data: profile } = await admin
      .from("user_profiles")
      .select("monitored_project_url")
      .eq("id", pro.userId)
      .maybeSingle();

    let projectRef: string | null = null;
    const monitored = profile?.monitored_project_url as string | null | undefined;
    if (monitored) {
      try {
        projectRef = new URL(monitored).hostname.split(".")[0] || null;
      } catch {
        projectRef = null;
      }
    }

    // Confirm the authorised account actually contains that project — a
    // mismatch means they authorised a different Supabase org.
    if (projectRef) {
      try {
        const projects = await listProjects(token.accessToken);
        if (!projects.some((p) => p.ref === projectRef)) projectRef = null;
      } catch {
        // Non-fatal: keep the ref we derived and let the scan surface any issue.
      }
    }

    const { error } = await admin
      .from("user_profiles")
      .update({
        supabase_mgmt_token_encrypted: encrypt(token.accessToken),
        supabase_mgmt_connection_epoch: newConnectionEpoch(),
        supabase_mgmt_refresh_encrypted: token.refreshToken ? encrypt(token.refreshToken) : null,
        supabase_mgmt_expires_at: token.expiresAt,
        supabase_mgmt_project_ref: projectRef,
        supabase_mgmt_connected_at: new Date().toISOString(),
      })
      .eq("id", pro.userId);

    if (error) return fail("error");
    return NextResponse.redirect(
      `${base}/dashboard/settings?supabase=${projectRef ? "connected" : "no_project"}`,
      { status: 303 }
    );
  } catch {
    return fail("error");
  }
}
