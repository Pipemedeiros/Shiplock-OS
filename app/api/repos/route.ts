import { NextResponse } from "next/server";
import { z } from "zod";
import { requireProUser } from "@/lib/deep/proGate";
import { getSupabaseAdmin } from "@/lib/supabase";
import { getInstallationToken, listRepos } from "@/lib/deep/github";

/**
 * The repositories this account's GitHub installation can see, merged with the
 * ones already chosen.
 *
 * Listing is live from GitHub rather than from our table: an installation's
 * repository set changes on GitHub's side, and showing a stale list would let
 * someone select a repository we can no longer read.
 */
export async function GET() {
  const user = await requireProUser();
  if (!user) return NextResponse.json({ error: "Not signed in." }, { status: 401 });

  const admin = getSupabaseAdmin();
  const { data: profile } = await admin
    .from("user_profiles")
    .select("github_installation_id")
    .eq("id", user.userId)
    .single();

  const installationId = profile?.github_installation_id as number | null;
  if (!installationId) {
    return NextResponse.json({ connected: false, repositories: [] });
  }

  const { data: stored } = await admin
    .from("repositories")
    .select("full_name, selected, last_audit_at")
    .eq("user_id", user.userId);

  const selected = new Map(
    (stored ?? []).map((r) => [r.full_name as string, r as { selected: boolean; last_audit_at: string | null }]),
  );

  try {
    const token = await getInstallationToken(installationId);
    const repos = await listRepos(token);

    return NextResponse.json({
      connected: true,
      repositories: repos.map((r) => ({
        fullName: r.fullName,
        defaultBranch: r.defaultBranch,
        isPrivate: r.isPrivate,
        selected: selected.get(r.fullName)?.selected ?? false,
        lastAuditAt: selected.get(r.fullName)?.last_audit_at ?? null,
      })),
    });
  } catch (err) {
    console.error("[api/repos] listing failed:", err instanceof Error ? err.message : err);
    // Never fall back to the stored list here. A transport failure that renders
    // as a short list looks identical to an installation that lost access.
    return NextResponse.json({ error: "Could not reach GitHub." }, { status: 502 });
  }
}

const SelectBody = z.object({
  repositories: z.array(z.string().regex(/^[\w.-]+\/[\w.-]+$/)).max(50),
});

/** Records which repositories to audit. Replaces the selection wholesale. */
export async function POST(request: Request) {
  const user = await requireProUser();
  if (!user) return NextResponse.json({ error: "Not signed in." }, { status: 401 });

  const parsed = SelectBody.safeParse(await request.json().catch(() => null));
  if (!parsed.success) {
    return NextResponse.json({ error: "Send a list of owner/name repositories." }, { status: 400 });
  }

  const admin = getSupabaseAdmin();
  const chosen = parsed.data.repositories;

  const { data: profile, error: profileError } = await admin
    .from("user_profiles")
    .select("github_installation_id")
    .eq("id", user.userId)
    .single();
  const installationId = profile?.github_installation_id as number | null;
  if (profileError || !installationId) {
    return NextResponse.json({ error: "Connect GitHub first." }, { status: 409 });
  }

  try {
    // Re-read the installation immediately before changing scope. A repository
    // name from the browser is a request, not proof that the installation can
    // still see it or that its default branch is "main".
    const available = new Map(
      (await listRepos(await getInstallationToken(installationId))).map((repository) => [
        repository.fullName,
        repository,
      ]),
    );
    if (chosen.some((fullName) => !available.has(fullName))) {
      return NextResponse.json(
        { error: "One or more repositories are no longer visible to this GitHub installation." },
        { status: 409 },
      );
    }

    const { data: rows, error } = await admin.rpc("replace_selected_repositories", {
      p_user: user.userId,
      p_repositories: chosen.map((fullName) => {
        const repository = available.get(fullName)!;
        return {
          full_name: repository.fullName,
          github_repo_id: repository.id,
          default_branch: repository.defaultBranch,
          private: repository.isPrivate ?? true,
        };
      }),
    });
    if (error) throw new Error("selection transaction failed");
    return NextResponse.json({ repositories: rows ?? [] });
  } catch {
    return NextResponse.json({ error: "Could not save the repository selection." }, { status: 503 });
  }
}
