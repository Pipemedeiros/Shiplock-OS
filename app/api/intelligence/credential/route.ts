import { NextResponse } from "next/server";
import { requireProUser } from "@/lib/deep/proGate";
import { readDatabaseBindingJson } from "@/lib/deep/databaseBindingRequest";
import { ApiKeyInput, getApiKeyStatus, removeApiKey, saveApiKey } from "@/lib/intelligence/credential";
import { crossSiteRefusal } from "@/lib/security/sameOrigin";

// The customer's own model key for API-key intelligence mode (10B-2e). The key
// arrives once in a POST body, is encrypted before storage, and is never
// echoed, logged, or returned: responses carry only its last 4 characters.
const signIn = () => NextResponse.json({ error: "Sign in to manage your AI key." }, { status: 403 });
const unavailable = () => NextResponse.json({ error: "AI key storage unavailable. Try again." }, { status: 503 });
const noStore = { headers: { "Cache-Control": "no-store" } };

export async function GET() {
  try {
    const pro = await requireProUser();
    if (!pro) return signIn();
    return NextResponse.json(await getApiKeyStatus(pro.userId), noStore);
  } catch { return unavailable(); }
}

export async function POST(request: Request) {
  const refused = crossSiteRefusal(request);
  if (refused) return refused;
  try {
    const pro = await requireProUser();
    if (!pro) return signIn();
    if (!/^application\/json(?:\s*;|$)/i.test(request.headers.get("content-type") ?? "")) {
      return NextResponse.json({ error: "Send the key as JSON." }, { status: 415 });
    }
    let input;
    try { input = ApiKeyInput.parse(await readDatabaseBindingJson(request)); }
    catch { return NextResponse.json({ error: "That does not look like an Anthropic API key." }, { status: 400 }); }
    return NextResponse.json(await saveApiKey(pro.userId, input.apiKey), noStore);
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
