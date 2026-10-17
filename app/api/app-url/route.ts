import { NextResponse } from "next/server";
import { z } from "zod";
import { requireProUser } from "@/lib/deep/proGate";
import { clearAppUrl, getAppUrlState, setAppUrl } from "@/lib/deep/appUrlStore";
import { queueCustomerRecheck } from "@/lib/jobs/manualRecheck";
import { crossSiteRefusal } from "@/lib/security/sameOrigin";

// The address the outside view reads (G3): the shipped bundle and exposed
// paths of the founder's own app, fetched read only, as a visitor gets them.
// GitHub's homepage is only suggested; nothing is probed until the founder
// confirms, and a confirm starts the read now rather than at the next pass.
// The repository it serves, when the founder names one, binds the live
// facts to that repository's findings (P5); none leaves them unjoined.
const Body = z.strictObject({ url: z.string().min(1).max(2048), repository: z.string().min(1).max(200).nullable().optional() });
const signIn = () => NextResponse.json({ error: "Sign in to set your app's address." }, { status: 403 });
const unavailable = () => NextResponse.json({ error: "Your app's address is unavailable. Try again." }, { status: 503 });
const noStore = { headers: { "Cache-Control": "no-store" } };

export async function GET() {
  try {
    const pro = await requireProUser();
    if (!pro) return signIn();
    return NextResponse.json(await getAppUrlState(pro.userId), noStore);
  } catch { return unavailable(); }
}

export async function POST(request: Request) {
  const refused = crossSiteRefusal(request);
  if (refused) return refused;
  try {
    const pro = await requireProUser();
    if (!pro) return signIn();
    let input;
    try { input = Body.parse(await request.json()); }
    catch { return NextResponse.json({ error: "Enter your app's public https address, like https://app.example.com." }, { status: 400 }); }
    let url: string;
    try { url = await setAppUrl(pro.userId, input.url, input.repository ?? null); }
    catch (err) {
      if (err instanceof Error && err.message === "invalid_repository") {
        return NextResponse.json({ error: "Choose one of the repositories you selected in ShipLock." }, { status: 400 });
      }
      if (err instanceof Error && err.message === "invalid_url") {
        return NextResponse.json({ error: "Enter your app's public https address, like https://app.example.com." }, { status: 400 });
      }
      throw err;
    }
    // The address is saved either way; a queue that is down only delays the read.
    const recheck = await queueCustomerRecheck(pro.userId, "app-surface").catch(() => null);
    return NextResponse.json({ url, recheck }, noStore);
  } catch { return unavailable(); }
}

export async function DELETE(request: Request) {
  const refused = crossSiteRefusal(request);
  if (refused) return refused;
  try {
    const pro = await requireProUser();
    if (!pro) return signIn();
    await clearAppUrl(pro.userId);
    return NextResponse.json({ url: null }, noStore);
  } catch { return unavailable(); }
}
