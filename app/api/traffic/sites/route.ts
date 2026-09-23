import { NextResponse } from "next/server";
import { z } from "zod";
import { requireProUser } from "@/lib/deep/proGate";
import { readDatabaseBindingJson } from "@/lib/deep/databaseBindingRequest";
import { crossSiteRefusal } from "@/lib/security/sameOrigin";
import { createTrafficSite, listTrafficSites, revokeTrafficSite } from "@/lib/traffic/sites";
import { buildExpressSnippet, buildSnippet, buildWebSnippet } from "@/lib/traffic/snippet";

// Repository-bound traffic sites (2F-2b). A site's token is shown once, inside
// its snippets, at creation; the list never returns tokens. To rotate, revoke
// and create again. Traffic never transits ShipLock: the snippet mirrors
// minimized metadata off the request path and fails open.
const Body = z.strictObject({ repositoryId: z.uuid(), host: z.string().min(1).max(253) });
const signIn = () => NextResponse.json({ error: "Sign in to manage traffic sites." }, { status: 403 });
const unavailable = () => NextResponse.json({ error: "Traffic sites are unavailable. Try again." }, { status: 503 });
const noStore = { headers: { "Cache-Control": "no-store" } };

export async function GET() {
  try {
    const pro = await requireProUser();
    if (!pro) return signIn();
    return NextResponse.json({ sites: await listTrafficSites(pro.userId) }, noStore);
  } catch { return unavailable(); }
}

export async function POST(request: Request) {
  const refused = crossSiteRefusal(request);
  if (refused) return refused;
  try {
    const pro = await requireProUser();
    if (!pro) return signIn();
    let input;
    try { input = Body.parse(await readDatabaseBindingJson(request)); }
    catch { return NextResponse.json({ error: "Choose a repository and enter your app's host, like app.example.com." }, { status: 400 }); }
    let site;
    try { site = await createTrafficSite(pro.userId, input.repositoryId, input.host); }
    catch (err) {
      const code = err instanceof Error ? err.message : "";
      if (code === "host_already_bound") return NextResponse.json({ error: "That host is already linked to another repository. Revoke it there first." }, { status: 409 });
      if (code === "invalid_host") return NextResponse.json({ error: "Enter a public hostname like app.example.com, without https:// or a path." }, { status: 400 });
      if (code === "repository_unavailable") return NextResponse.json({ error: "That repository is not selected." }, { status: 404 });
      throw err;
    }
    const origin = process.env.NEXT_PUBLIC_APP_URL || new URL(request.url).origin;
    return NextResponse.json({ siteId: site.siteId, ingestToken: site.ingestToken, snippets: {
      nextjs: buildSnippet(site.ingestToken, origin),
      web: buildWebSnippet(site.ingestToken, origin),
      express: buildExpressSnippet(site.ingestToken, origin),
    } }, noStore);
  } catch { return unavailable(); }
}

export async function DELETE(request: Request) {
  const refused = crossSiteRefusal(request);
  if (refused) return refused;
  try {
    const pro = await requireProUser();
    if (!pro) return signIn();
    const id = z.uuid().safeParse(new URL(request.url).searchParams.get("id"));
    if (!id.success) return NextResponse.json({ error: "Name a traffic site." }, { status: 400 });
    return NextResponse.json({ ok: await revokeTrafficSite(pro.userId, id.data) });
  } catch { return unavailable(); }
}
