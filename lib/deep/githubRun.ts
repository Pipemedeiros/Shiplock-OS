import { scanPublicCredentialValues } from "./clientExposure";
import { listTree, getFile, queryOsv, listRecentCommitPatches, type Repo } from "./github";
import { scanSecrets, extractDependencies, depFindings, type RepoFile, type GithubFinding } from "./githubScan";
import { scanCredentialHandling } from "./credentialHandling";
import { scanNextConfigEnv } from "./nextConfigEnv";
import { checkRepoVisibility } from "./repoVisibility";
import { collectRoutes } from "@/lib/graph/routeInventory";
import { buildReachabilityIndex } from "@/lib/graph/reachability";
import { scanRouteFacts } from "@/lib/graph/routeChecks";
import { scanWorkflows } from "./workflowScan";
import { fullyRead, historyFindings, scanPatches, MAX_COMMITS } from "./historyScan";
import type { RepositorySourceSnapshot } from "@/lib/graph/graphRun";
import type { RouteFact } from "@/lib/graph/routeInventory";

// Full source scan for a connected GitHub App installation: read-only repo
// contents -> committed secrets, Next.js config env
// exposure, workflow structure (pull_request_target RCE, unpinned actions,
// missing permissions), dependency CVEs (via OSV). Persists only NEW findings
// into the shared deep_findings table (source='github'), same only-new +
// archive-on-disconnect contract as runVercelEnvAudit. A single unreadable
// repo/file never fails the whole pass.
// Persisted finding IDs retain their remediation routes in lib/fixes.

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
  readStats?: { filesAttempted: number; filesRead: number },
  historySink?: string[]
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

  for (const c of candidates) {
    const content = await getFile(token, fullName, c.path, branch).catch(() => null);
    if (content == null) continue;
    files.push({ path: c.path, content });
  }
  // The shallowest manifest is the app's (a root lockfile also covers its
  // workspaces), and only its own directory's lockfile pins its versions. The
  // tree lists mcp/package.json before package.json, so "first seen" once
  // checked a subpackage in place of the app.
  const manifest = files
    .filter((file) => /(^|\/)package\.json$/.test(file.path))
    .sort((a, b) => a.path.split("/").length - b.path.split("/").length)[0];
  const packageJson = manifest?.content ?? null;
  const packageLock = manifest
    ? files.find((file) => file.path === manifest.path.replace(/package\.json$/, "package-lock.json"))?.content ?? null
    : null;
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
    historySink?.push(...fullyRead(commits));
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

export interface CollectedRepositorySource {
  snapshot: RepositorySourceSnapshot;
  findings: GithubFinding[];
  /** Commits the history check read in full; empty when history was unread. */
  historyRead: string[];
}

/** Pure collection boundary for one selected repository. Persistence and job
 * fencing belong to the caller. A failed collection returns no empty snapshot. */
export async function collectRepositorySource(
  token: string,
  repo: Repo,
  repositoryId: string,
  installationId: string | number,
): Promise<CollectedRepositorySource> {
  const routes: RouteFact[] = [];
  const liveFiles = new Set<string>();
  const dependencies = new Map<string,string>();
  const stats = { filesAttempted: 0, filesRead: 0 };
  const historyRead: string[] = [];
  const findings = await scanRepo(token,repo,routes,liveFiles,dependencies,stats,historyRead);
  return {
    findings,
    historyRead,
    snapshot: {
      repositoryId,
      ...(repo.id ? { providerRepositoryId: repo.id } : {}),
      repositoryFullName: repo.fullName,
      installationId: String(installationId),
      ref: repo.defaultBranch,
      recordedAt: new Date().toISOString(),
      completeness: "partial",
      ...stats,
      routes,
      liveFiles: [...liveFiles],
      hasEntryPoints: liveFiles.size > 0,
      dependencies: [...dependencies].map(([name,version]) => ({name,version})),
    },
  };
}
