import {
  getInstallationToken, getFile, queryOsv,
  getBranchSha, createBranch, getFileSha, putFile, openPullRequest, findOpenPullRequestForBranch,
} from "./github";
import { createHash } from "crypto";
import { getSupabaseAdmin } from "@/lib/supabase";
import { extractDependencies } from "./githubScan";
import { planDependencyBumps, pickTargetVersion, buildPrBody } from "./githubFix";
import { openedOutcome, type RepairOutcome } from "@/lib/fixes/repairOutcome";

// Opens a dependency-bump fix PR for one repository. NEVER pushes to the
// default branch (always a new branch), never merges, only edits package.json
// version ranges.

interface FixPr {
  repo: string;
  url: string;
  count: number; // number of deps bumped
}

async function fixRepo(token: string, fullName: string, branch: string): Promise<FixPr | null> {
  const packageJson = await getFile(token, fullName, "package.json", branch).catch(() => null);
  if (!packageJson) return null;
  const packageLock = await getFile(token, fullName, "package-lock.json", branch).catch(() => null);

  const deps = extractDependencies(packageJson, packageLock);
  const osv = await queryOsv(deps);

  const targets = osv
    .map((r) => ({ name: r.dep.name, version: pickTargetVersion(r.vulns) }))
    .filter((t): t is { name: string; version: string } => t.version !== null);

  const { updated, changes } = planDependencyBumps(packageJson, targets);
  if (changes.length === 0) return null;

  // New branch off the default branch's tip — never touch the default itself.
  const fixBranch = `shiplock/dep-fixes-${createHash("sha256").update(updated).digest("hex").slice(0, 20)}`;
  const recovered = await findOpenPullRequestForBranch(token, fullName, fixBranch);
  if (recovered) return { repo: fullName, url: recovered, count: changes.length };
  const baseSha = await getBranchSha(token, fullName, branch);
  const existingBranch = await getBranchSha(token, fullName, fixBranch).then(() => true).catch(() => false);
  if (!existingBranch) await createBranch(token, fullName, fixBranch, baseSha);

  const fileSha = await getFileSha(token, fullName, "package.json", fixBranch);
  if (!fileSha) return null;
  const existingContent = await getFile(token, fullName, "package.json", fixBranch).catch(() => null);
  if (existingContent !== updated) {
    await putFile(
      token, fullName, "package.json", fixBranch, updated, fileSha,
      "chore(deps): bump vulnerable dependencies (ShipLock)"
    );
  }

  const url = await openPullRequest(
    token, fullName, fixBranch, branch,
    `Fix ${changes.length} vulnerable ${changes.length === 1 ? "dependency" : "dependencies"} (ShipLock)`,
    buildPrBody(changes)
  );
  return { repo: fullName, url, count: changes.length };
}

/**
 * One customer click, one dependency-bump PR: the selected
 * repository named on the repair receipt, every vulnerable package with a known
 * patched version bumped at once. Runs inside the repair worker's lease.
 */
export async function openDependencyBumpPr(userId: string, repositoryId: string): Promise<RepairOutcome> {
  const admin = getSupabaseAdmin();
  const [{ data: profile }, { data: repo }] = await Promise.all([
    admin.from("user_profiles").select("github_installation_id").eq("id", userId).maybeSingle(),
    admin.from("repositories").select("full_name, default_branch")
      .eq("id", repositoryId).eq("user_id", userId).eq("selected", true).maybeSingle(),
  ]);
  const installationId = profile?.github_installation_id as string | number | null | undefined;
  if (!installationId || !repo) return { status: "failed", code: "repository_unavailable" };
  const token = await getInstallationToken(installationId);
  const pr = await fixRepo(token, repo.full_name as string, repo.default_branch as string);
  return pr ? openedOutcome(pr.url) : { status: "failed", code: "no_changes" };
}
