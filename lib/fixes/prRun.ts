import { createHash } from "crypto";
import { getSupabaseAdmin } from "@/lib/supabase";
import { getInstallationToken, listRepos, getBranchSha, createBranch, putFile, openPullRequest, findOpenPullRequestForBranch, getFile, getFileSha, listTree } from "@/lib/deep/github";
import { fixLane, type FixableFinding } from "./lane";
import { applyCodemod, hasCodemod } from "./codemods";
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
  token: string, repo: string, defaultBranch: string, artifact: FixArtifact, title: string, body: string,
  idempotencyMaterial = `${artifact.path}\0${artifact.content}`,
): Promise<string> {
  const branch = `shiplock/fix-${createHash("sha256").update(idempotencyMaterial).digest("hex").slice(0, 20)}`;
  const recovered = await findOpenPullRequestForBranch(token, repo, branch);
  if (recovered) return recovered;
  const baseSha = await getBranchSha(token, repo, defaultBranch);
  const existingBranch = await getBranchSha(token, repo, branch).then(() => true).catch(() => false);
  if (!existingBranch) await createBranch(token, repo, branch, baseSha);
  const existingFile = await getFileSha(token, repo, artifact.path, branch);
  const existingContent = existingFile ? await getFile(token, repo, artifact.path, branch).catch(() => null) : null;
  if (existingContent !== artifact.content) {
    await putFile(token, repo, artifact.path, branch, artifact.content, existingFile ?? undefined, title);
  }
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

  const { data: selectedRows, error: selectedError } = await admin
    .from("repositories")
    .select("full_name")
    .eq("user_id", userId)
    .eq("selected", true);
  if (selectedError) throw new Error("Selected repositories could not be read.");
  const selected = new Set((selectedRows ?? []).map((row) => row.full_name as string));

  const wanted = repoFromFindingId(finding.id);
  const exactName = wanted ?? (selected.size === 1 ? [...selected][0] : null);
  if (!exactName) throw new Error("Choose the repository for this finding before opening a pull request.");
  if (!selected.has(exactName)) throw new Error("The finding repository is not selected.");
  const repo = repos.find((candidate) => candidate.fullName === exactName);
  if (!repo) throw new Error("The selected repository is no longer accessible to ShipLock.");

  // A REAL fix where the change is mechanical. Committing an edited version of
  // the customer's own file means they review a diff of their code, not a note
  // telling them to make the change themselves — which was the copy-paste
  // problem wearing a PR as a costume.
  if (!editedContent && hasCodemod(finding)) {
    const url = await openCodemodPr(token, repo.fullName, repo.defaultBranch, finding);
    if (url) return { url };
    // Fall through to the fix-request PR when the transform found nothing to
    // change. Better an honest description than an empty diff.
  }

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

  const url = await openFixPr(token, repo.fullName, repo.defaultBranch, artifact, title, body, `${userId}\0${finding.id}\0${artifact.content}`);
  return { url };
}


/**
 * Opens a PR containing the actual edited files.
 *
 * Returns null when the codemod changed nothing, so the caller can fall back to
 * a fix-request PR. An empty PR would be worse than instructions: it looks like
 * we did something.
 */
export async function openCodemodPr(
  token: string,
  repo: string,
  defaultBranch: string,
  finding: FixableFinding
): Promise<string | null> {
  // Only files the codemod could plausibly touch, so a fix PR never reads more
  // of the customer's repository than the change requires.
  const tree = await listTree(token, repo, defaultBranch).catch(() => []);
  const candidates = tree
    .filter((t) => /(^|\/)(next\.config\.(ts|js|mjs)|\.env(\.[\w-]+)?)$/.test(t.path) || /\.(ts|tsx|js|jsx)$/.test(t.path))
    .slice(0, 200);

  const files: { path: string; content: string }[] = [];
  for (const entry of candidates) {
    const content = await getFile(token, repo, entry.path, defaultBranch).catch(() => null);
    if (content !== null) files.push({ path: entry.path, content });
  }

  const { results, description } = applyCodemod(finding, files);
  if (results.length === 0) return null;

  const branch = `shiplock/fix-${Date.now()}`;
  const baseSha = await getBranchSha(token, repo, defaultBranch);
  await createBranch(token, repo, branch, baseSha);

  const title = `ShipLock: ${finding.title}`;
  for (const result of results) {
    // Existing file → its blob sha is required, or the contents API rejects the
    // write rather than silently overwriting someone else's change.
    const sha = await getFileSha(token, repo, result.path, branch);
    await putFile(token, repo, result.path, branch, result.content, sha ?? undefined, title);
  }

  const body =
    `Automated by ShipLock for **${finding.title}** (${finding.severity}).\n\n` +
    `This PR contains the actual change — ${description} — across ${results.length} file${results.length === 1 ? "" : "s"}, ` +
    `so you are reviewing a diff of your own code rather than instructions.\n\n` +
    `Every change here is mechanical: the correct result is determined by the input, with no judgement about what your app is meant to do. ` +
    `Anything that needs that judgement is never machine-authored — it comes to you as a draft PR instead.\n\n` +
    `Revert by closing this PR.` +
    (/public_prefixed_secret/.test(finding.id)
      ? `\n\n**This does not rotate the key.** Renaming the variable stops it being inlined into future builds, but the value that already shipped is public — rotate it with the provider.`
      : "");

  return openPullRequest(token, repo, branch, defaultBranch, title, body);
}
