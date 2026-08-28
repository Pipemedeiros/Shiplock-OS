import { NextResponse } from "next/server";
import { z } from "zod";
import { requireProUser } from "@/lib/deep/proGate";
import { getSupabaseAdmin } from "@/lib/supabase";
import {
  createBranch,
  getBranchSha,
  getInstallationToken,
  openPullRequest,
  putFile,
} from "@/lib/deep/github";
import { getOpenFindings } from "@/lib/agent/dashboardData";
import { fixBranchName, fixDocument, fixFilePath, fixTitle } from "@/lib/agent/fixPr";

/**
 * Opens a pull request for one finding.
 *
 * Always a NEW branch off the default, never a push to the default itself and
 * never a merge. That boundary is not a setting.
 */
const Body = z.object({ findingId: z.string().min(1).max(400) });

export async function POST(request: Request) {
  const user = await requireProUser();
  if (!user) return NextResponse.json({ error: "Not signed in." }, { status: 401 });

  const parsed = Body.safeParse(await request.json().catch(() => null));
  if (!parsed.success) return NextResponse.json({ error: "Name a finding." }, { status: 400 });

  // Read the finding from OUR record rather than from the request. The client
  // sends an id and nothing else; the title, the evidence and the file that end
  // up in a pull request on the customer's repository all come from the row.
  const findings = await getOpenFindings(user.userId);
  const finding = findings.find((f) => f.id === parsed.data.findingId);
  if (!finding) return NextResponse.json({ error: "No such finding." }, { status: 404 });

  if (finding.fixKind === "manual") {
    return NextResponse.json(
      { error: "This one is a decision about your architecture, so there is no pull request to open." },
      { status: 409 },
    );
  }
  if (finding.fixPrUrl) {
    return NextResponse.json({ url: finding.fixPrUrl, alreadyOpen: true });
  }

  const admin = getSupabaseAdmin();
  const { data: profile } = await admin
    .from("user_profiles")
    .select("github_installation_id")
    .eq("id", user.userId)
    .single();

  const installationId = profile?.github_installation_id as number | null;
  if (!installationId || !finding.repository) {
    return NextResponse.json({ error: "Connect GitHub first." }, { status: 409 });
  }

  try {
    const token = await getInstallationToken(installationId);
    const { data: repoRow } = await admin
      .from("repositories")
      .select("default_branch")
      .eq("user_id", user.userId)
      .eq("full_name", finding.repository)
      .maybeSingle();

    const base = (repoRow?.default_branch as string) ?? "main";
    const branch = fixBranchName(finding.id);
    const sha = await getBranchSha(token, finding.repository, base);

    await createBranch(token, finding.repository, branch, sha);
    await putFile(
      token,
      finding.repository,
      fixFilePath(finding.id),
      branch,
      fixDocument(finding),
      undefined,
      `ShipLock: ${finding.title}`,
    );

    const url = await openPullRequest(
      token,
      finding.repository,
      branch,
      base,
      fixTitle(finding),
      fixDocument(finding),
    );

    const number = Number(url.split("/").pop());
    await admin
      .from("deep_findings")
      .update({ fix_pr_url: url, fix_pr_number: Number.isFinite(number) ? number : null })
      .eq("id", finding.rowId);

    return NextResponse.json({ url, number });
  } catch (err) {
    console.error("[api/fix/pr] failed:", err instanceof Error ? err.message : err);
    return NextResponse.json({ error: "Could not open the pull request." }, { status: 502 });
  }
}
