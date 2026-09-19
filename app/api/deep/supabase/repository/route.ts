import { NextResponse } from "next/server";
import { requireProUser } from "@/lib/deep/proGate";
import { SupabaseBindingCollector, SupabaseRepositoryConfirmation, changeSupabaseRepositoryBinding,
  getSupabaseRepositoryBindings } from "@/lib/deep/supabaseRepositoryBinding";
import { readDatabaseBindingJson } from "@/lib/deep/databaseBindingRequest";

const unavailable = () => NextResponse.json({ error: "Database association unavailable. Try again." }, { status: 503 });
export async function GET(request: Request) {
  try {
    const pro = await requireProUser();
    if (!pro) return NextResponse.json({ error: "Sign in to manage database associations." }, { status: 403 });
    const params = new URL(request.url).searchParams;
    const collector = SupabaseBindingCollector.safeParse(params.get("collector"));
    if (!collector.success || params.getAll("collector").length !== 1 || [...params.keys()].some((key) => key !== "collector")) {
      return NextResponse.json({ error: "Select one Supabase access path." }, { status: 400 });
    }
    return NextResponse.json(await getSupabaseRepositoryBindings(pro.userId, collector.data), { headers: { "Cache-Control": "no-store" } });
  } catch { return unavailable(); }
}

export async function POST(request: Request) {
  try {
    const pro = await requireProUser();
    if (!pro) return NextResponse.json({ error: "Sign in to manage database associations." }, { status: 403 });
    if (request.headers.get("origin") !== new URL(request.url).origin) {
      return NextResponse.json({ error: "A same-origin request is required." }, { status: 403 });
    }
    if (!/^application\/json(?:\s*;|$)/i.test(request.headers.get("content-type") ?? "")) {
      return NextResponse.json({ error: "Send a JSON confirmation." }, { status: 415 });
    }
    let input;
    try { input = SupabaseRepositoryConfirmation.parse(await readDatabaseBindingJson(request)); }
    catch { return NextResponse.json({ error: "Invalid confirmation." }, { status: 400 }); }
    const result = await changeSupabaseRepositoryBinding(pro.userId, input);
    if (result === "stale") return NextResponse.json({ error: "The connection or repository changed. Reload before confirming." }, { status: 409 });
    return NextResponse.json({ ok: true, collector: input.collector, method: "customer_confirmed" });
  } catch { return unavailable(); }
}
