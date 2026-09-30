import { NextResponse } from "next/server";
import { getSupabaseAdmin } from "@/lib/supabase";

// Q31: liveness for an external uptime monitor. One indexed head read of a
// tiny table, bounded to 3 s; the body says only up or down.
export const dynamic = "force-dynamic";

export async function GET() {
  let up = false;
  try {
    const read = Promise.resolve(getSupabaseAdmin().from("user_profiles").select("id", { head: true }).limit(1))
      .then((r) => ({ error: r.error !== null }), () => ({ error: true }));
    const timeout = new Promise<{ error: boolean }>((resolve) => setTimeout(() => resolve({ error: true }), 3000));
    const result = await Promise.race([read, timeout]);
    up = !result.error;
  } catch {
    up = false;
  }
  return NextResponse.json({ ok: up, database: up ? "up" : "down" }, { status: up ? 200 : 503, headers: { "cache-control": "no-store" } });
}
