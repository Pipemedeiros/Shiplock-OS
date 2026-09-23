import { NextResponse } from "next/server";
import { requireProUser } from "@/lib/deep/proGate";
import { readDatabaseBindingJson } from "@/lib/deep/databaseBindingRequest";
import { ConnectionApproval, approveIntelligenceConnection, getIntelligenceConnection,
  revokeIntelligenceConnection } from "@/lib/intelligence/connection";
import { isSameOrigin } from "@/lib/security/sameOrigin";

// The customer's standing approval for their own intelligence host (10B-2b).
// Cookie-authenticated; mutations require the browser's same-origin decision.
const signIn = () => NextResponse.json({ error: "Sign in to manage your AI connection." }, { status: 403 });
const unavailable = () => NextResponse.json({ error: "AI connection unavailable. Try again." }, { status: 503 });
const crossSite = (request: Request) => !isSameOrigin(request);

export async function GET() {
  try {
    const pro = await requireProUser();
    if (!pro) return signIn();
    return NextResponse.json(await getIntelligenceConnection(pro.userId), { headers: { "Cache-Control": "no-store" } });
  } catch { return unavailable(); }
}

export async function POST(request: Request) {
  try {
    const pro = await requireProUser();
    if (!pro) return signIn();
    if (crossSite(request)) return NextResponse.json({ error: "A same-origin request is required." }, { status: 403 });
    if (!/^application\/json(?:\s*;|$)/i.test(request.headers.get("content-type") ?? "")) {
      return NextResponse.json({ error: "Send a JSON approval." }, { status: 415 });
    }
    let approval;
    try { approval = ConnectionApproval.parse(await readDatabaseBindingJson(request)); }
    catch { return NextResponse.json({ error: "Invalid approval." }, { status: 400 }); }
    await approveIntelligenceConnection(pro.userId, approval);
    return NextResponse.json(await getIntelligenceConnection(pro.userId), { headers: { "Cache-Control": "no-store" } });
  } catch { return unavailable(); }
}

export async function DELETE(request: Request) {
  try {
    const pro = await requireProUser();
    if (!pro) return signIn();
    if (crossSite(request)) return NextResponse.json({ error: "A same-origin request is required." }, { status: 403 });
    return NextResponse.json({ ok: true, ...(await revokeIntelligenceConnection(pro.userId)) });
  } catch { return unavailable(); }
}
