import { NextRequest, NextResponse } from "next/server";
import { getSupabaseAdmin } from "@/lib/supabase";
import { generateToken } from "@/lib/apiTokens";
import { hasProductAccess } from "@/lib/access";
import { quotaCode, quotaResponse } from "@/lib/quota";
import { bearerMfaOk } from "@/lib/mfa";

// Manage ShipLock PATs (for the MCP integration). Session-Bearer auth (the
// dashboard), product-access gated. POST creates + returns the raw token ONCE; GET lists
// metadata (never the token); DELETE revokes by id.

async function requireProductUser(req: NextRequest): Promise<
  { error: NextResponse } | { userId: string; admin: ReturnType<typeof getSupabaseAdmin> }
> {
  const token = req.headers.get("authorization")?.replace("Bearer ", "");
  if (!token) return { error: NextResponse.json({ error: "Authentication required." }, { status: 401 }) };
  const admin = getSupabaseAdmin();
  const { data: auth } = await admin.auth.getUser(token);
  if (!auth.user) return { error: NextResponse.json({ error: "Authentication required." }, { status: 401 }) };
  if (!bearerMfaOk(auth.user, token)) return { error: NextResponse.json({ error: "Enter the code from your authenticator app first." }, { status: 403 }) };
  const { data: profile } = await admin.from("user_profiles").select("is_paid").eq("id", auth.user.id).maybeSingle();
  if (!hasProductAccess(profile)) return { error: NextResponse.json({ error: "Product access unavailable." }, { status: 402 }) };
  return { userId: auth.user.id, admin };
}

export async function POST(req: NextRequest) {
  const ctx = await requireProductUser(req);
  if ("error" in ctx) return ctx.error;

  let name = "MCP token";
  try {
    const body = (await req.json()) as { name?: string };
    if (typeof body.name === "string" && body.name.trim()) name = body.name.trim().slice(0, 60);
  } catch { /* default name */ }

  const { raw, hash } = generateToken();
  const { error } = await ctx.admin.from("api_tokens").insert({ user_id: ctx.userId, token_hash: hash, name });
  if (error) {
    // Provisional cap of 10 active tokens (migration 083).
    const code = quotaCode(error.message);
    return quotaResponse(code ? new Error(code) : null) ?? NextResponse.json({ error: "Could not create token." }, { status: 500 });
  }

  // Raw token returned ONCE — never retrievable again.
  return NextResponse.json({ token: raw, name });
}

export async function GET(req: NextRequest) {
  const ctx = await requireProductUser(req);
  if ("error" in ctx) return ctx.error;
  const { data } = await ctx.admin
    .from("api_tokens")
    .select("id, name, created_at, last_used_at")
    .eq("user_id", ctx.userId)
    .is("revoked_at", null)
    .order("created_at", { ascending: false });
  return NextResponse.json({ tokens: data ?? [] });
}

export async function DELETE(req: NextRequest) {
  const ctx = await requireProductUser(req);
  if ("error" in ctx) return ctx.error;
  const id = new URL(req.url).searchParams.get("id");
  if (!id) return NextResponse.json({ error: "Missing token id." }, { status: 400 });
  await ctx.admin.from("api_tokens").update({ revoked_at: new Date().toISOString() }).eq("id", id).eq("user_id", ctx.userId);
  return NextResponse.json({ ok: true });
}
