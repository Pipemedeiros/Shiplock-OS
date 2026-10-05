import { NextResponse } from "next/server";
import { requireProUser } from "@/lib/deep/proGate";
import { getApiKeyStatus, removeApiKey } from "@/lib/intelligence/credential";
import { crossSiteRefusal } from "@/lib/security/sameOrigin";

// A model key saved for the retired API-key mode (Felipe, 2026-10-01: ShipLock
// runs no model). Its status (last 4 characters only) and its removal; no key
// can be saved any more.
const signIn = () => NextResponse.json({ error: "Sign in to manage your AI key." }, { status: 403 });
const unavailable = () => NextResponse.json({ error: "AI key storage unavailable. Try again." }, { status: 503 });

export async function GET() {
  try {
    const pro = await requireProUser();
    if (!pro) return signIn();
    return NextResponse.json(await getApiKeyStatus(pro.userId), { headers: { "Cache-Control": "no-store" } });
  } catch { return unavailable(); }
}

export async function DELETE(request: Request) {
  const refused = crossSiteRefusal(request);
  if (refused) return refused;
  try {
    const pro = await requireProUser();
    if (!pro) return signIn();
    await removeApiKey(pro.userId);
    return NextResponse.json({ ok: true });
  } catch { return unavailable(); }
}
