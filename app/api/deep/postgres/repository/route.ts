import { NextResponse } from "next/server";
import { requireProUser } from "@/lib/deep/proGate";
import { DirectRepositoryConfirmation, changeDirectRepositoryBinding, getDirectRepositoryBindings } from "@/lib/deep/databaseRepositoryBinding";
import { readDatabaseBindingJson } from "@/lib/deep/databaseBindingRequest";
import { crossSiteRefusal } from "@/lib/security/sameOrigin";

const unavailable = () => NextResponse.json({ error: "Database association unavailable. Try again." }, { status: 503 });

export async function GET() {
  try {
    const pro = await requireProUser();
    if (!pro) return NextResponse.json({ error: "Sign in to manage database associations." }, { status: 403 });
    return NextResponse.json(await getDirectRepositoryBindings(pro.userId), { headers: { "Cache-Control": "no-store" } });
  } catch { return unavailable(); }
}

export async function POST(request: Request) {
  const refused = crossSiteRefusal(request);
  if (refused) return refused;
  try {
    const pro = await requireProUser();
    if (!pro) return NextResponse.json({ error: "Sign in to manage database associations." }, { status: 403 });
    // Cookie-authenticated mutation: an opaque connection fingerprint is not
    // a CSRF token or authority. Require the browser's same-origin decision.
    if (!/^application\/json(?:\s*;|$)/i.test(request.headers.get("content-type") ?? "")) {
      return NextResponse.json({ error: "Send a JSON confirmation." }, { status: 415 });
    }
    let input;
    try { input = DirectRepositoryConfirmation.parse(await readDatabaseBindingJson(request)); }
    catch { return NextResponse.json({ error: "Invalid confirmation." }, { status: 400 }); }
    const result = await changeDirectRepositoryBinding(pro.userId, input);
    if (result === "stale") return NextResponse.json({ error: "The connection or repository changed. Reload before confirming." }, { status: 409 });
    return NextResponse.json({ ok: true, method: "customer_confirmed" });
  } catch { return unavailable(); }
}
