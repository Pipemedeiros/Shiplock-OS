import { getSupabaseAdmin } from "@/lib/supabase";
import { getInstallationToken, listRepos, listTree, getFile, queryOsv } from "./github";
import { scanSecrets, scanTokenStorage, scanLoggedSecrets, extractDependencies, depFindings, type RepoFile, type GithubFinding } from "./githubScan";
import { scanCodePatterns } from "./sourcePatterns";
import { scanClientExposure } from "./clientExposure";

// Full source scan for a connected GitHub App installation: read-only repo
// contents -> committed secrets, token-storage anti-pattern, dependency CVEs
// (via OSV). Persists only NEW findings into the shared deep_findings table
// (source='github'), same only-new + archive-on-disconnect contract as
// runVercelEnvAudit. A single unreadable repo/file never fails the whole pass.

const MAX_REPOS = 10;
const MAX_FILES_PER_REPO = 60;
const MAX_FILE_BYTES = 200_000; // skip large/binary blobs

// Files worth reading for secret / token-storage detection, plus manifests.
const CANDIDATE_RE = /(^|\/)(\.env(\.[\w-]+)?|package\.json|package-lock\.json|.*\.(ts|tsx|js|jsx|mjs|cjs|json|ya?ml|env)|.*\.pem)$/i;

// Read order matters because MAX_FILES_PER_REPO truncates. The tree arrives in
// directory-traversal order, so on a repo with a large app/ directory the cap
// used to fall before the root manifests — silently disabling dependency
// scanning — and before lib/, which breaks the import chains scanClientExposure
// walks from client components. Rank by what each check needs first:
//   0  dotenv files and manifests: tiny, and every secret/dependency check
//      depends on them. Never let these be the files we drop.
//   1  application source: where client components and their imports live.
//   2  everything else the candidate filter allowed.
export function readPriority(path: string): number {
  if (/(^|\/)(\.env(\.[\w-]+)?|package(-lock)?\.json)$/i.test(path)) return 0;
  if (/^(src\/|app\/|components\/|lib\/|pages\/|utils\/|server\/)/i.test(path)) return 1;
  return 2;
}

async function scanRepo(token: string, fullName: string, branch: string): Promise<GithubFinding[]> {
  const tree = await listTree(token, fullName, branch);
  const candidates = tree
    .filter((t) => t.size <= MAX_FILE_BYTES && CANDIDATE_RE.test(t.path))
    // Stable within a priority band, so the set we read is deterministic and a
    // finding doesn't appear and vanish between passes.
    .map((t, index) => ({ t, index, rank: readPriority(t.path) }))
    .sort((a, b) => a.rank - b.rank || a.index - b.index)
    .map((entry) => entry.t)
    .slice(0, MAX_FILES_PER_REPO);

  const files: RepoFile[] = [];
  let packageJson: string | null = null;
  let packageLock: string | null = null;

  for (const c of candidates) {
    const content = await getFile(token, fullName, c.path, branch).catch(() => null);
    if (content == null) continue;
    files.push({ path: c.path, content });
    if (/(^|\/)package\.json$/.test(c.path) && !packageJson) packageJson = content;
    if (/(^|\/)package-lock\.json$/.test(c.path) && !packageLock) packageLock = content;
  }

  const findings: GithubFinding[] = [
    ...scanSecrets(files),
    ...scanTokenStorage(files),
    ...scanLoggedSecrets(files),
    ...scanCodePatterns(files),
    ...scanClientExposure(files),
  ];

  if (packageJson) {
    const deps = extractDependencies(packageJson, packageLock);
    try {
      findings.push(...depFindings(await queryOsv(deps)));
    } catch {
      /* OSV unavailable — skip dep findings for this repo, keep the rest */
    }
  }

  // Namespace finding ids by repo so the same issue in two repos stays distinct.
  return findings.map((f) => ({ ...f, id: `${fullName}::${f.id}` }));
}

export async function runGithubScan(
  userId: string,
  installationId: string | number
): Promise<{ total: number; newCount: number }> {
  const admin = getSupabaseAdmin();
  const token = await getInstallationToken(installationId);
  const repos = (await listRepos(token)).slice(0, MAX_REPOS);

  const all: GithubFinding[] = [];
  for (const repo of repos) {
    try {
      all.push(...(await scanRepo(token, repo.fullName, repo.defaultBranch)));
    } catch {
      continue; // one bad repo shouldn't fail the pass
    }
  }

  const { data: existing } = await admin
    .from("deep_findings")
    .select("finding_id")
    .eq("user_id", userId)
    .eq("source", "github")
    .is("archived_at", null);
  const activeIds = new Set((existing ?? []).map((r) => r.finding_id as string));

  const fresh = all.filter((f) => !activeIds.has(f.id));
  if (fresh.length > 0) {
    await admin.from("deep_findings").insert(
      fresh.map((f) => ({
        user_id: userId, source: "github", finding_id: f.id,
        severity: f.severity, title: f.title, consequence: f.consequence,
        package_name: f.packageName, version: f.version, vuln_id: f.vulnId, cve_id: f.cveId,
      }))
    );
  }
  return { total: all.length, newCount: fresh.length };
}
