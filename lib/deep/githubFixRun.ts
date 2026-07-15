import {
  getInstallationToken, listRepos, getFile, queryOsv,
  getBranchSha, createBranch, getFileSha, putFile, openPullRequest,
} from "./github";
import { extractDependencies } from "./githubScan";
import { planDependencyBumps, pickTargetVersion, buildPrBody } from "./githubFix";

// Opens dependency-bump fix PRs for a connected installation. One PR per repo
// that has vulnerable deps with known fixes. NEVER pushes to the default branch
// (always a new branch), never merges, only edits package.json version ranges.
// A single failing repo never aborts the others.
const MAX_REPOS = 10;

export interface FixPr {
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
  const fixBranch = `shiplock/dep-fixes-${Date.now()}`;
  const baseSha = await getBranchSha(token, fullName, branch);
  await createBranch(token, fullName, fixBranch, baseSha);

  const fileSha = await getFileSha(token, fullName, "package.json", branch);
  if (!fileSha) return null;
  await putFile(
    token, fullName, "package.json", fixBranch, updated, fileSha,
    "chore(deps): bump vulnerable dependencies (ShipLock)"
  );

  const url = await openPullRequest(
    token, fullName, fixBranch, branch,
    `Fix ${changes.length} vulnerable ${changes.length === 1 ? "dependency" : "dependencies"} (ShipLock)`,
    buildPrBody(changes)
  );
  return { repo: fullName, url, count: changes.length };
}

export async function runGithubFix(installationId: string | number): Promise<{ prs: FixPr[]; repos: number }> {
  const token = await getInstallationToken(installationId);
  const repos = (await listRepos(token)).slice(0, MAX_REPOS);

  const prs: FixPr[] = [];
  for (const repo of repos) {
    try {
      const pr = await fixRepo(token, repo.fullName, repo.defaultBranch);
      if (pr) prs.push(pr);
    } catch {
      continue; // one repo's failure never blocks the rest
    }
  }
  return { prs, repos: repos.length };
}
