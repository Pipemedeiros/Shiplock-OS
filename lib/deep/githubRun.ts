import { scanPublicCredentialValues } from "./clientExposure";
import { getSupabaseAdmin } from "@/lib/supabase";
import { getInstallationToken, listRepos, listTree, getFile, queryOsv, listRecentCommitPatches, type Repo } from "./github";
import { scanSecrets, extractDependencies, depFindings, type RepoFile, type GithubFinding } from "./githubScan";
import { scanCredentialHandling } from "./credentialHandling";
import { scanNextConfigEnv } from "./nextConfigEnv";
import { checkRepoVisibility } from "./repoVisibility";
import { collectRoutes } from "@/lib/graph/routeInventory";
import { buildReachabilityIndex } from "@/lib/graph/reachability";
import { scanRouteFacts } from "@/lib/graph/routeChecks";
import { scanWorkflows } from "./workflowScan";
import { historyFindings, scanPatches, MAX_COMMITS } from "./historyScan";
import { saveFacts, type RepositorySourceSnapshot } from "@/lib/graph/graphRun";
import type { RouteFact } from "@/lib/graph/routeInventory";

// Full source scan for a connected GitHub App installation: read-only repo
// contents -> committed secrets, Next.js config env
// exposure, workflow structure (pull_request_target RCE, unpinned actions,
// missing permissions), dependency CVEs (via OSV). Persists only NEW findings
// into the shared deep_findings table (source='github'), same only-new +
// archive-on-disconnect contract as runVercelEnvAudit. A single unreadable
// repo/file never fails the whole pass.
// Persisted finding IDs retain their remediation routes in lib/fixes.

const MAX_REPOS = 10;
const MAX_FILES_PER_REPO = 60;
const MAX_FILE_BYTES = 200_000; // skip large/binary blobs

// Files worth reading for credential detection, plus manifests.
const CANDIDATE_RE = /(^|\/)(\.env(\.[\w-]+)?|package\.json|package-lock\.json|.*\.(ts|tsx|js|jsx|mjs|cjs|json|ya?ml|env)|.*\.pem)$/i;

// Read order matters because MAX_FILES_PER_REPO truncates. The tree arrives in
// directory-traversal order, so on a repo with a large app/ directory the cap
// used to fall before the root manifests — silently disabling dependency
// scanning — and before lib/, which the route collector (collectRoutes, below)
// walks import chains through to resolve ownership scoping. Rank by what each
// check needs first:
//   0  dotenv files and manifests: tiny, and every secret/dependency check
//      depends on them. Never let these be the files we drop.
//   1  application source: where routes and the imports they resolve live.
//   2  everything else the candidate filter allowed.
export function readPriority(path: string): number {
  if (/(^|\/)(\.env(\.[\w-]+)?|package(-lock)?\.json)$/i.test(path)) return 0;
  if (/^(src\/|app\/|components\/|lib\/|pages\/|utils\/|server\/)/i.test(path)) return 1;
  return 2;
}

async function scanRepo(
  token: string,
  repo: Repo,
  routeSink?: RouteFact[],
  liveFileSink?: Set<string>,
  depSink?: Map<string, string>,
  readStats?: { filesAttempted: number; filesRead: number }
): Promise<GithubFinding[]> {
  const { fullName, defaultBranch: branch } = repo;
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
  if (readStats) {
    readStats.filesAttempted = candidates.length;
    readStats.filesRead = files.length;
  }

  const findings: GithubFinding[] = [
    ...scanSecrets(files),
    ...scanNextConfigEnv(files),
    ...scanPublicCredentialValues(files),
    ...scanCredentialHandling(files),
    // C20 — CI is a live attack path, and workflow files are already in the set
    // we fetch (.ya?ml matches the candidate filter).
    ...scanWorkflows(files),
  ];

  if (packageJson) {
    const deps = extractDependencies(packageJson, packageLock);
    // Kept for the scheduled CVE re-check (F1), which must work without a push.
    if (depSink) for (const d of deps) depSink.set(d.name, d.version);
    try {
      findings.push(...depFindings(await queryOsv(deps)));
    } catch {
      /* OSV unavailable — skip dep findings for this repo, keep the rest */
    }
  }

  // Feed the graph's source collector. Routes are facts, not findings — they
  // go to graph_facts, never to deep_findings.
  if (routeSink) {
    const routes = collectRoutes(files);
    routeSink.push(...routes);

    // C12/C13 — findings the inventory already has the facts for. sourceOf
    // returns undefined for a file we did not read, and unknown is never a
    // finding.
    const byPath = new Map(files.map((file) => [file.path, file.content]));
    findings.push(...scanRouteFacts(routes, (path) => byPath.get(path)));
    // C6: which files this repo actually reaches from an entry point. Computed
    // here because this is the only point the repo contents exist in memory.
    if (liveFileSink) {
      const index = buildReachabilityIndex({ files, routes });
      if (index.hasEntryPoints) for (const f of index.liveFiles) liveFileSink.add(f);
    }
  }

  // C2 — secrets in history. Runs after the working-tree scan so it can skip
  // anything still present there, which the committed-secrets check already
  // reports. Bounded to a recent window; see listRecentCommitPatches.
  try {
    const stillPresent = new Set(
      findings
        .map((finding) => /^github:secret:([a-z_]+):/.exec(finding.id)?.[1])
        .filter((id): id is string => id !== undefined)
    );
    const commits = await listRecentCommitPatches(token, fullName, branch, MAX_COMMITS);
    findings.push(...historyFindings(scanPatches(commits), repo.isPrivate === false, stillPresent));
  } catch {
    // History is best-effort — never let it cost us the rest of the scan.
  }

  // C22 last, because it READS the findings above: a public repo is only a
  // critical problem when we also found credentials in it. Runs before the id
  // namespacing below so its secret-class matching sees the bare ids.
  findings.push(...checkRepoVisibility(repo, findings));

  // Namespace finding ids by repo so the same issue in two repos stays distinct.
  return findings.map((f) => ({ ...f, id: `${fullName}::${f.id}` }));
}

export async function runGithubScan(
  userId: string,
  installationId: string | number
): Promise<{ total: number; newCount: number; resolvedCount: number }> {
  const admin = getSupabaseAdmin();
  const token = await getInstallationToken(installationId);
  const repos = (await listRepos(token)).slice(0, MAX_REPOS);

  const all: GithubFinding[] = [];
  // Which repos we actually finished reading. Load-bearing for archiving below:
  // a repo that threw produced ZERO findings, and treating that as "everything in
  // it is fixed" would silently close real open issues.
  const scannedRepos: string[] = [];
  const routes: RouteFact[] = [];
  const liveFiles = new Set<string>();
  const deps = new Map<string, string>();
  const repositories: RepositorySourceSnapshot[] = [];
  for (const repo of repos) {
    // Repository-local sinks prevent identical paths/dependency names from
    // erasing provenance, and never publish a failed scan's mutated sinks.
    const repoRoutes: RouteFact[] = [];
    const repoLiveFiles = new Set<string>();
    const repoDeps = new Map<string, string>();
    const stats = { filesAttempted: 0, filesRead: 0 };
    try {
      all.push(...(await scanRepo(token, repo, repoRoutes, repoLiveFiles, repoDeps, stats)));
      scannedRepos.push(repo.fullName);
      routes.push(...repoRoutes);
      for (const file of repoLiveFiles) liveFiles.add(file);
      for (const [name, version] of repoDeps) deps.set(name, version);
      repositories.push({
        repositoryFullName: repo.fullName,
        installationId: String(installationId),
        ref: repo.defaultBranch,
        recordedAt: new Date().toISOString(),
        completeness: "partial",
        ...stats,
        routes: repoRoutes,
        liveFiles: [...repoLiveFiles],
        hasEntryPoints: repoLiveFiles.size > 0,
        dependencies: [...repoDeps].map(([name, version]) => ({ name, version })),
      });
    } catch {
      continue; // one bad repo shouldn't fail the pass
    }
  }

  // Only record routes when at least one repo was actually read. Saving an
  // empty inventory after a failed pass would tell the reasoner the customer has
  // no API at all, silently closing every path that runs through one.
  if (scannedRepos.length > 0) {
    await saveFacts(userId, "source", {
      routes,
      repositories,
      liveFiles: [...liveFiles],
      // False when no repo yielded an entry point, which makes every
      // reachability verdict `unknown` rather than demoting everything at once.
      hasEntryPoints: liveFiles.size > 0,
      dependencies: [...deps].map(([name, version]) => ({ name, version })),
    }, {
      completeness: "partial",
      reason: "Source collection uses repository, file, and history limits; complete coverage is not established.",
    });
  }

  const { data: existing } = await admin
    .from("deep_findings")
    .select("finding_id")
    .eq("user_id", userId)
    .eq("source", "github")
    .is("archived_at", null);
  const activeIds = new Set((existing ?? []).map((r) => r.finding_id as string));

  // Re-verify after merge. Without this, a customer merges the fix PR we opened
  // and the finding stays CRITICAL forever — the dashboard and the weekly digest
  // both keep counting work that is already done, which teaches people our
  // findings don't track reality. The per-PR webhook already re-runs this scan on
  // every pull request, so merging a fix is itself the re-check; all that was
  // missing is closing what no longer reproduces.
  //
  // Scoped to repos we SUCCESSFULLY scanned, for the reason above. Finding ids
  // are namespaced `owner/name::…` by scanRepo, which is what makes this
  // scoping possible.
  const currentIds = new Set(all.map((f) => f.id));
  const resolved = [...activeIds].filter(
    (id) => !currentIds.has(id) && scannedRepos.some((fullName) => id.startsWith(`${fullName}::`))
  );
  if (resolved.length > 0) {
    await admin
      .from("deep_findings")
      .update({ archived_at: new Date().toISOString() })
      .eq("user_id", userId)
      .eq("source", "github")
      .is("archived_at", null)
      .in("finding_id", resolved);
  }

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
  return { total: all.length, newCount: fresh.length, resolvedCount: resolved.length };
}
