import { getSupabaseAdmin } from "@/lib/supabase";
import {
  getInstallationToken, listRepos, getBranchSha, createBranch, putFile, openPullRequest,
} from "@/lib/deep/github";
import { fixLane, type FixableFinding } from "./lane";
import { buildMigrationFix, buildCodeFix, type FixArtifact } from "./content";

// Opens ONE reviewable PR per fix. Mirrors githubFixRun's safety: always a new
// branch off the default (never touches default, never merges). The committed
// file is a migration (.sql) for DB/RLS fixes or a fix-request markdown for
// code/logic fixes — the customer reviews, (optionally edited already), merges,
// and their own deploy applies it. ShipLock never writes their DB directly.

export interface FixPrResult {
  url: string;
}

// Low-level: commit one artifact to a fresh branch and open a PR. Pure w.r.t.
// the github.ts client so it's unit-testable with mocked deps.
export async function openFixPr(
  token: string, repo: string, defaultBranch: string, artifact: FixArtifact, title: string, body: string
): Promise<string> {
  const branch = `shiplock/fix-${Date.now()}`;
  const baseSha = await getBranchSha(token, repo, defaultBranch);
  await createBranch(token, repo, branch, baseSha);
  // New file → no sha (create, not update).
  await putFile(token, repo, artifact.path, branch, artifact.content, undefined, title);
  return openPullRequest(token, repo, branch, defaultBranch, title, body);
}

// Source-finding ids are namespaced `<owner/repo>::<id>` (see githubRun). Pull
// the repo out so the PR lands in the right repo; null for non-repo findings.
function repoFromFindingId(id: string): string | null {
  const i = id.indexOf("::");
  return i > 0 ? id.slice(0, i) : null;
}

// Orchestration: resolve the installation + repo, build the artifact (content
// overridden by the user's edited version), open the PR. Throws a clear error
// when GitHub isn't connected — the route maps it to a friendly message.
export async function runFixPr(
  userId: string, finding: FixableFinding, editedContent: string
): Promise<FixPrResult> {
  const lane = fixLane(finding);
  if (lane.method === "dep-pr" || lane.method === "deep-link") {
    throw new Error("This fix isn't applied through this route.");
  }

  const admin = getSupabaseAdmin();
  const { data: profile } = await admin
    .from("user_profiles")
    .select("github_installation_id")
    .eq("id", userId)
    .maybeSingle();
  const installationId = profile?.github_installation_id as string | number | null | undefined;
  if (!installationId) throw new Error("GitHub is not connected.");

  const token = await getInstallationToken(installationId);
  const repos = await listRepos(token);
  if (repos.length === 0) throw new Error("No accessible repositories.");

  const wanted = repoFromFindingId(finding.id);
  const repo = repos.find((r) => r.fullName === wanted) ?? repos[0];

  // Build the artifact for its path, then swap in the user's edited content.
  const base = lane.method === "migration-pr" ? buildMigrationFix(finding) : buildCodeFix(finding);
  const artifact: FixArtifact = { path: base.path, content: editedContent || base.content };

  const title =
    lane.method === "migration-pr"
      ? `ShipLock: ${finding.title} (migration)`
      : `ShipLock fix request: ${finding.title}`;
  const body =
    `Automated by ShipLock for the finding **${finding.title}** (${finding.severity}).\n\n` +
    (lane.method === "migration-pr"
      ? "Review the migration, then merge — your own deploy applies it. ShipLock never writes to your database directly."
      : "This PR is a fix request describing the exact change. Apply it (your coding agent can, straight from the file), then merge.");

  const url = await openFixPr(token, repo.fullName, repo.defaultBranch, artifact, title, body);
  return { url };
}
