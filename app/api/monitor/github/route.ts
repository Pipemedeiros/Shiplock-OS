import { NextRequest, NextResponse } from "next/server";
import { createHmac, timingSafeEqual } from "crypto";
import { getSupabaseAdmin } from "@/lib/supabase";
import { runGithubScan } from "@/lib/deep/githubRun";

// GitHub App webhook — re-scans a repo's source on every pull request, so the
// watch re-audits "every PR" (replacing the old deploy-webhook trigger). The
// GitHub App's webhook URL points here; auth is the App's signed payload
// (X-Hub-Signature-256, HMAC over the raw body with GITHUB_WEBHOOK_SECRET).
// Inert until the secret is set. Always 200s (GitHub retries on non-2xx and a
// scan failure must not cause a retry storm).

const RESCAN_ACTIONS = new Set(["opened", "reopened", "synchronize", "ready_for_review"]);

function verify(raw: string, sigHeader: string | null, secret: string): boolean {
  if (!sigHeader) return false;
  const expected = "sha256=" + createHmac("sha256", secret).update(raw).digest("hex");
  const a = Buffer.from(expected);
  const b = Buffer.from(sigHeader);
  return a.length === b.length && timingSafeEqual(a, b);
}

export async function POST(req: NextRequest) {
  const secret = process.env.GITHUB_WEBHOOK_SECRET;
  if (!secret) return NextResponse.json({ ok: true }); // not configured — inert

  const raw = await req.text();
  if (!verify(raw, req.headers.get("x-hub-signature-256"), secret)) {
    return NextResponse.json({ error: "bad signature" }, { status: 401 });
  }

  const event = req.headers.get("x-github-event");
  if (event !== "pull_request") return NextResponse.json({ ok: true });

  let payload: { action?: string; installation?: { id?: number } };
  try {
    payload = JSON.parse(raw);
  } catch {
    return NextResponse.json({ ok: true });
  }

  const installationId = payload.installation?.id;
  if (!payload.action || !RESCAN_ACTIONS.has(payload.action) || !installationId) {
    return NextResponse.json({ ok: true });
  }

  // Map the installation to its (paid) owner, then re-scan.
  try {
    const admin = getSupabaseAdmin();
    const { data: profile } = await admin
      .from("user_profiles")
      .select("id, is_paid")
      .eq("github_installation_id", installationId)
      .maybeSingle();
    if (profile?.is_paid) {
      await runGithubScan(profile.id as string, installationId);
    }
  } catch (err) {
    console.error("[monitor/github] PR re-scan failed:", err instanceof Error ? err.message : err);
  }

  return NextResponse.json({ ok: true });
}
