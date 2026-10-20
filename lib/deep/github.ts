import { AsyncLocalStorage } from "node:async_hooks";
import { createSign } from "crypto";
import { env } from "@/lib/env";
import type { Severity } from "@/lib/types";
import type { Dep, OsvVuln } from "./githubScan";
import { fixedVersionFromOsv } from "./githubFix";

// GitHub App API access. Collection is read-only. Separate, customer-approved
// repair paths can write a new branch and open a pull request; they never write
// the default branch or merge. All functions throw a clear error at call time
// if the App is not configured.
const API = "https://api.github.com";
const TIMEOUT_MS = 12_000;
const GH_HEADERS = { Accept: "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28" };

function b64url(input: Buffer | string): string {
  return Buffer.from(input).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// Short-lived (10-min) App JWT, RS256-signed with the App private key. Node
// crypto only — no JWT dependency added.
function appJwt(): string {
  const appId = env.GITHUB_APP_ID;
  const privateKey = env.GITHUB_APP_PRIVATE_KEY;
  if (!appId || !privateKey) throw new Error("GITHUB_APP_ID and GITHUB_APP_PRIVATE_KEY must be set");

  const now = Math.floor(Date.now() / 1000);
  const header = b64url(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const payload = b64url(JSON.stringify({ iat: now - 60, exp: now + 540, iss: appId }));
  const signature = b64url(
    createSign("RSA-SHA256").update(`${header}.${payload}`).sign(privateKey.replace(/\\n/g, "\n"))
  );
  return `${header}.${payload}.${signature}`;
}

// Exchange the App JWT for a short-lived installation access token.
export interface InstallationAccess {
  token: string;
  permissions: Record<string, string>;
}

export const REQUIRED_GITHUB_APP_PERMISSIONS = {
  metadata: "read",
  contents: "write",
  pull_requests: "write",
  checks: "write",
} as const;

const permissionRank: Record<string, number> = { none: 0, read: 1, write: 2, admin: 3 };

export function missingInstallationPermissions(permissions: Record<string, string>): string[] {
  return Object.entries(REQUIRED_GITHUB_APP_PERMISSIONS)
    .filter(([name, required]) => (permissionRank[permissions[name] ?? "none"] ?? 0) < permissionRank[required])
    .map(([name]) => name);
}

export async function getInstallationAccess(installationId: string | number): Promise<InstallationAccess> {
  const res = await fetch(`${API}/app/installations/${installationId}/access_tokens`, {
    method: "POST",
    headers: { ...GH_HEADERS, Authorization: `Bearer ${appJwt()}` },
    signal: AbortSignal.timeout(TIMEOUT_MS),
  });
  if (!res.ok) throw new Error(`GitHub installation token HTTP ${res.status}`);
  const json = (await res.json()) as { token?: unknown; permissions?: unknown };
  if (typeof json.token !== "string" || !json.token) throw new Error("GitHub installation token missing");
  const permissions = json.permissions && typeof json.permissions === "object" && !Array.isArray(json.permissions)
    ? Object.fromEntries(Object.entries(json.permissions).filter((entry): entry is [string, string] => typeof entry[1] === "string"))
    : {};
  return { token: json.token, permissions };
}

export async function getInstallationToken(installationId: string | number): Promise<string> {
  return (await getInstallationAccess(installationId)).token;
}

export interface Repo {
  /** GitHub-issued repository identity. Stringified to avoid bigint precision loss. */
  id: string | null;
  fullName: string; // owner/name
  defaultBranch: string;
  /**
   * Whether GitHub reports the repo as private. `null` when the field is absent
   * from the response — treated as unknown, never as public, so we can't invent
   * a "your repo is public" alarm out of a missing field.
   */
  isPrivate: boolean | null;
  /** GitHub's own label: "public" | "private" | "internal". Null if absent. */
  visibility: string | null;
}

export async function listRepos(token: string): Promise<Repo[]> {
  const res = await fetch(`${API}/installation/repositories?per_page=100`, {
    headers: { ...GH_HEADERS, Authorization: `token ${token}` },
    signal: AbortSignal.timeout(TIMEOUT_MS),
  });
  if (!res.ok) throw new Error(`GitHub list repos HTTP ${res.status}`);
  const json = (await res.json()) as {
    repositories?: Array<{
      id?: number | string;
      full_name: string;
      default_branch: string;
      private?: boolean;
      visibility?: string;
    }>;
  };
  return (json.repositories ?? []).map((r) => ({
    id: typeof r.id === "number" || typeof r.id === "string" ? String(r.id) : null,
    fullName: r.full_name,
    defaultBranch: r.default_branch,
    isPrivate: typeof r.private === "boolean" ? r.private : null,
    visibility: typeof r.visibility === "string" ? r.visibility : null,
  }));
}

export interface TreeEntry { path: string; size: number }

// Recursive git tree — used to pick candidate files to scan (bounded by size).
export async function listTree(token: string, fullName: string, branch: string): Promise<TreeEntry[]> {
  const res = await fetch(`${API}/repos/${fullName}/git/trees/${encodeURIComponent(branch)}?recursive=1`, {
    headers: { ...GH_HEADERS, Authorization: `token ${token}` },
    signal: AbortSignal.timeout(TIMEOUT_MS),
  });
  if (!res.ok) throw new Error(`GitHub tree HTTP ${res.status}`);
  const json = (await res.json()) as { tree?: Array<{ path: string; type: string; size?: number }> };
  return (json.tree ?? []).filter((t) => t.type === "blob").map((t) => ({ path: t.path, size: t.size ?? 0 }));
}

/** In preview, a branch the lane "created" reads as its base commit, and a
 * file the lane already "wrote" reads as what it wrote (Q13). */
function previewRef(branch: string): string {
  return previewStore.getStore()?.branches.get(branch) ?? branch;
}
function previewWritten(path: string, branch: string): string | undefined {
  const recording = previewStore.getStore();
  if (!recording?.branches.has(branch)) return undefined;
  return recording.files.findLast((file) => file.path === path)?.content;
}

export async function getFile(token: string, fullName: string, path: string, branch: string): Promise<string | null> {
  const written = previewWritten(path, branch);
  if (written !== undefined) return written;
  const res = await fetch(`${API}/repos/${fullName}/contents/${path.split("/").map(encodeURIComponent).join("/")}?ref=${encodeURIComponent(previewRef(branch))}`, {
    headers: { ...GH_HEADERS, Authorization: `token ${token}` },
    signal: AbortSignal.timeout(TIMEOUT_MS),
  });
  if (!res.ok) return null;
  const json = (await res.json()) as { content?: string; encoding?: string };
  if (json.encoding !== "base64" || !json.content) return null;
  return Buffer.from(json.content, "base64").toString("utf8");
}

/** File names directly in a directory on a branch; empty when the directory
 * does not exist. Any other failure throws, so a caller never mistakes it for
 * an empty directory. */
export async function listDirectory(token: string, fullName: string, dir: string, branch: string): Promise<string[]> {
  const res = await fetch(`${API}/repos/${fullName}/contents/${dir.split("/").map(encodeURIComponent).join("/")}?ref=${encodeURIComponent(previewRef(branch))}`, {
    headers: { ...GH_HEADERS, Authorization: `token ${token}` },
    signal: AbortSignal.timeout(TIMEOUT_MS),
  });
  if (res.status === 404) return [];
  if (!res.ok) throw new Error(`GitHub contents HTTP ${res.status}`);
  const json = (await res.json()) as unknown;
  return Array.isArray(json) ? json.filter((e) => e?.type === "file" && typeof e.name === "string").map((e) => e.name as string) : [];
}

// ── OSV.dev dependency-vulnerability lookup (free, no API key) ──────────────
function mapOsvSeverity(raw: string | null): Severity {
  if (!raw) return "WARNING";
  const s = raw.toUpperCase();
  if (s === "CRITICAL" || s === "HIGH") return "CRITICAL";
  return "WARNING";
}

// Two-step to stay cheap: querybatch tells us WHICH deps have vulns (one call
// for all deps), then we enrich only the (usually few) hits with full detail.
export async function queryOsv(deps: Dep[]): Promise<{ dep: Dep; vulns: OsvVuln[] }[]> {
  if (deps.length === 0) return [];

  // OSV takes at most 1,000 queries per batch; a 1 MB lockfile holds ~2,000.
  const results: Array<{ vulns?: Array<{ id: string }> }> = [];
  for (let start = 0; start < deps.length; start += 1000) {
    const batchRes = await fetch("https://api.osv.dev/v1/querybatch", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        queries: deps.slice(start, start + 1000).map((d) => ({ package: { name: d.name, ecosystem: "npm" }, version: d.version })),
      }),
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    if (!batchRes.ok) throw new Error(`OSV querybatch HTTP ${batchRes.status}`);
    const batch = (await batchRes.json()) as { results?: Array<{ vulns?: Array<{ id: string }> }> };
    const page = batch.results ?? [];
    for (let i = 0; i < Math.min(1000, deps.length - start); i++) results.push(page[i] ?? {});
  }

  const out: { dep: Dep; vulns: OsvVuln[] }[] = [];
  for (let i = 0; i < deps.length; i++) {
    const ids = (results[i]?.vulns ?? []).map((v) => v.id);
    if (ids.length === 0) continue;
    const vulns: OsvVuln[] = [];
    for (const id of ids.slice(0, 10)) {
      try {
        const vRes = await fetch(`https://api.osv.dev/v1/vulns/${id}`, { signal: AbortSignal.timeout(TIMEOUT_MS) });
        if (!vRes.ok) continue;
        const v = (await vRes.json()) as {
          id: string; summary?: string; aliases?: string[];
          database_specific?: { severity?: string };
          severity?: Array<{ type: string; score: string }>;
          affected?: unknown;
        };
        const cve = (v.aliases ?? []).find((a) => a.startsWith("CVE-")) ?? null;
        vulns.push({
          id: v.id,
          cveId: cve,
          summary: v.summary ?? "Known vulnerability.",
          severity: mapOsvSeverity(v.database_specific?.severity ?? null),
          fixedVersion: fixedVersionFromOsv(v.affected, deps[i].name),
        });
      } catch {
        /* skip a single un-enrichable vuln */
      }
    }
    if (vulns.length > 0) out.push({ dep: deps[i], vulns });
  }
  return out;
}

// ── Write flow (fix PRs) ───────────────────────────────────────────────────
// Used ONLY to open pull requests for dependency bumps. Never pushes to the
// default branch and never merges. Requires the App's Contents + Pull requests
// write permissions (see AGENTS.md).

// Preview mode (Q13 / Step 8): a repair lane runs its real planning code, but
// every write is recorded here instead of sent, and the lane stops at "open
// pull request", so nothing after it (such as recording the PR) runs. Outside
// capturePreview nothing changes. Only ghWrite and the PR-recovery read
// consult it, so a new write helper must go through ghWrite.
export type PreviewCapture =
  | { status: "planned"; token: string; repository: string; branch: string; base: string; title: string; body: string;
      files: { path: string; content: string }[] }
  | { status: "already_open"; url: string }
  | { status: "not_planned"; result: unknown };
type Recording = { token: string; files: { path: string; content: string }[]; branches: Map<string, string> };
const previewStore = new AsyncLocalStorage<Recording>();
class PreviewStop extends Error {
  constructor(readonly capture: PreviewCapture) { super("preview stop"); }
}

export async function capturePreview(lane: () => Promise<unknown>): Promise<PreviewCapture> {
  try {
    const result = await previewStore.run({ token: "", files: [], branches: new Map() }, lane);
    return { status: "not_planned", result };
  } catch (err) {
    if (err instanceof PreviewStop) return err.capture;
    throw err;
  }
}

function recordWrite(recording: Recording, token: string, path: string, method: string, body: unknown): unknown {
  recording.token = token;
  const payload = (body ?? {}) as { content?: string; title?: string; head?: string; base?: string; body?: string };
  const contents = /^\/repos\/([^/]+\/[^/]+)\/contents\/(.+)$/.exec(path);
  if (method === "PUT" && contents) {
    recording.files.push({ path: contents[2].split("/").map(decodeURIComponent).join("/"),
      content: Buffer.from(payload.content ?? "", "base64").toString("utf8") });
    return {};
  }
  const pulls = /^\/repos\/([^/]+\/[^/]+)\/pulls$/.exec(path);
  if (method === "POST" && pulls) {
    throw new PreviewStop({ status: "planned", token, repository: pulls[1], branch: payload.head ?? "", base: payload.base ?? "",
      title: payload.title ?? "", body: payload.body ?? "", files: recording.files });
  }
  if (method === "POST" && /\/git\/refs$/.test(path)) {
    const ref = payload as { ref?: string; sha?: string };
    if (ref.ref?.startsWith("refs/heads/") && ref.sha) recording.branches.set(ref.ref.slice("refs/heads/".length), ref.sha);
    return {};
  }
  // Any other write in preview mode is refused, never sent.
  throw new Error(`GitHub ${method} ${path} is not allowed in preview`);
}

async function ghWrite(token: string, path: string, method: string, body: unknown) {
  const recording = previewStore.getStore();
  if (recording) return recordWrite(recording, token, path, method, body);
  const res = await fetch(`${API}${path}`, {
    method,
    headers: { ...GH_HEADERS, Authorization: `token ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(TIMEOUT_MS),
  });
  if (!res.ok) throw new Error(`GitHub ${method} ${path} HTTP ${res.status}`);
  return res.json();
}

// SHA the branch currently points at (base for the new branch).
export async function getBranchSha(token: string, fullName: string, branch: string): Promise<string> {
  const created = previewStore.getStore()?.branches.get(branch);
  if (created) return created;
  const res = await fetch(`${API}/repos/${fullName}/git/ref/heads/${encodeURIComponent(branch)}`, {
    headers: { ...GH_HEADERS, Authorization: `token ${token}` },
    signal: AbortSignal.timeout(TIMEOUT_MS),
  });
  if (!res.ok) throw new Error(`GitHub get ref HTTP ${res.status}`);
  const json = (await res.json()) as { object?: { sha?: string } };
  if (!json.object?.sha) throw new Error("GitHub ref missing sha");
  return json.object.sha;
}

export async function createBranch(token: string, fullName: string, branch: string, sha: string): Promise<void> {
  await ghWrite(token, `/repos/${fullName}/git/refs`, "POST", { ref: `refs/heads/${branch}`, sha });
}

// Current blob sha of a file on a branch — required to update it via contents API.
export async function getFileSha(token: string, fullName: string, path: string, branch: string): Promise<string | null> {
  const res = await fetch(
    `${API}/repos/${fullName}/contents/${path.split("/").map(encodeURIComponent).join("/")}?ref=${encodeURIComponent(previewRef(branch))}`,
    { headers: { ...GH_HEADERS, Authorization: `token ${token}` }, signal: AbortSignal.timeout(TIMEOUT_MS) }
  );
  if (!res.ok) return null;
  const json = (await res.json()) as { sha?: string };
  return json.sha ?? null;
}

export async function putFile(
  // sha is omitted when creating a NEW file (migrations / fix-request files);
  // required when updating an existing one. JSON.stringify drops undefined, so
  // the GitHub contents API sees no `sha` on create, which is what it wants.
  token: string, fullName: string, path: string, branch: string, contentUtf8: string, sha: string | undefined, message: string
): Promise<void> {
  await ghWrite(token, `/repos/${fullName}/contents/${path.split("/").map(encodeURIComponent).join("/")}`, "PUT", {
    message,
    content: Buffer.from(contentUtf8, "utf8").toString("base64"),
    sha,
    branch,
  });
}

export const SHIPLOCK_PR_LABEL = "ShipLock";

export async function openPullRequest(
  token: string, fullName: string, head: string, base: string, title: string, body: string
): Promise<string> {
  const pr = (await ghWrite(token, `/repos/${fullName}/pulls`, "POST", { title, head, base, body })) as {
    html_url?: string; number?: number;
  };
  if (!pr.html_url) throw new Error("GitHub PR missing html_url");
  // A5 (Felipe 2026-10-07): label it "ShipLock" so it reads as ShipLock's in the
  // customer's PR list and CI. Best effort: a refused label never fails the PR.
  if (typeof pr.number === "number") {
    await ghWrite(token, `/repos/${fullName}/issues/${pr.number}/labels`, "POST", { labels: [SHIPLOCK_PR_LABEL] }).catch(() => undefined);
  }
  return pr.html_url;
}

/** Recover an already-open ShipLock PR after a lost response. GitHub does not
 * make POST /pulls idempotent, so callers pair this with a deterministic head. */
export async function findOpenPullRequestForBranch(
  token: string, fullName: string, branch: string,
): Promise<string | null> {
  const owner = fullName.split("/")[0];
  const res = await fetch(
    `${API}/repos/${fullName}/pulls?state=open&head=${encodeURIComponent(`${owner}:${branch}`)}&per_page=10`,
    { headers: { ...GH_HEADERS, Authorization: `token ${token}` }, signal: AbortSignal.timeout(TIMEOUT_MS) },
  );
  if (!res.ok) throw new Error(`GitHub list pull requests HTTP ${res.status}`);
  const rows = (await res.json()) as Array<{ html_url?: unknown }>;
  const url = typeof rows[0]?.html_url === "string" ? rows[0].html_url : null;
  if (url && previewStore.getStore()) throw new PreviewStop({ status: "already_open", url });
  return url;
}

export interface PullRequestMeta {
  headRef: string;
  headRepository: string | null;
  /** False for a fork: ShipLock cannot push a fix branch into it. */
  sameRepository: boolean;
  title: string;
  url: string;
}

/** Read-only PR metadata for a stored review (8B-1): the head branch a
 * before-merge fix targets, and whether that branch lives in a fork. */
export async function getPullRequest(token: string, fullName: string, number: number): Promise<PullRequestMeta> {
  const res = await fetch(`${API}/repos/${fullName}/pulls/${number}`, {
    headers: { ...GH_HEADERS, Authorization: `token ${token}` }, signal: AbortSignal.timeout(TIMEOUT_MS),
  });
  if (!res.ok) throw new Error(`GitHub read pull request HTTP ${res.status}`);
  const pr = await res.json() as { title?: unknown; html_url?: unknown; head?: { ref?: unknown; repo?: { full_name?: unknown } | null } };
  if (typeof pr.head?.ref !== "string" || typeof pr.title !== "string" || typeof pr.html_url !== "string") {
    throw new Error("GitHub returned an unexpected pull request shape");
  }
  const headRepository = typeof pr.head.repo?.full_name === "string" ? pr.head.repo.full_name : null;
  return {
    headRef: pr.head.ref, headRepository,
    sameRepository: headRepository?.toLowerCase() === fullName.toLowerCase(),
    title: pr.title.slice(0, 500), url: pr.html_url,
  };
}

/**
 * The customer's own check runs on a pull request's current head (Q2 / 8-CI).
 * Read-only: two GETs. ShipLock's own check is excluded, so this is only what
 * the customer's CI reported. Legacy commit statuses need a permission the
 * App does not request, so they are invisible here, never "passing".
 */
export async function listPullRequestCheckRuns(
  token: string, fullName: string, number: number, signal?: AbortSignal,
): Promise<{ status: string; conclusion: string | null }[]> {
  const headers = { ...GH_HEADERS, Authorization: `token ${token}` };
  const timeout = () => signal ? AbortSignal.any([signal, AbortSignal.timeout(10_000)]) : AbortSignal.timeout(10_000);
  const pr = await fetch(`${API}/repos/${fullName}/pulls/${number}`, { headers, signal: timeout() });
  if (!pr.ok) throw new Error(`GitHub read pull request HTTP ${pr.status}`);
  const sha = ((await pr.json()) as { head?: { sha?: unknown } }).head?.sha;
  if (typeof sha !== "string" || !/^[a-f0-9]{40}$/.test(sha)) throw new Error("GitHub returned an unexpected pull request shape");
  const res = await fetch(`${API}/repos/${fullName}/commits/${sha}/check-runs?filter=latest&per_page=100`, { headers, signal: timeout() });
  if (!res.ok) throw new Error(`GitHub list check runs HTTP ${res.status}`);
  const body = (await res.json()) as { check_runs?: Array<{ name?: unknown; status?: unknown; conclusion?: unknown }> };
  return (body.check_runs ?? [])
    .filter((run) => run.name !== "ShipLock" && typeof run.status === "string")
    .map((run) => ({ status: run.status as string, conclusion: typeof run.conclusion === "string" ? run.conclusion : null }));
}

/**
 * Recent commits with their diffs, for the history secret scan (C2).
 *
 * HARD BOUNDED, because this is the most expensive thing we ask GitHub for: one
 * API call per commit. A repository can have a hundred thousand commits, and
 * walking them would be both slow and rude. We look at the most recent window
 * only — enough to catch the mistake that was made and "fixed" this month, which
 * is the one still worth catching.
 */
export async function listRecentCommitPatches(
  token: string,
  fullName: string,
  branch: string,
  maxCommits: number
): Promise<{ sha: string; message: string; patch: string; date: string; complete: boolean }[]> {
  const perPage = Math.min(maxCommits, 100);
  const listRes = await fetch(
    `${API}/repos/${fullName}/commits?sha=${encodeURIComponent(branch)}&per_page=${perPage}`,
    { headers: { ...GH_HEADERS, Authorization: `token ${token}` }, signal: AbortSignal.timeout(TIMEOUT_MS) }
  );
  if (!listRes.ok) return [];

  const list = (await listRes.json()) as {
    sha?: string;
    commit?: { message?: string; author?: { date?: string } };
  }[];
  if (!Array.isArray(list)) return [];

  const out: { sha: string; message: string; patch: string; date: string; complete: boolean }[] = [];

  for (const entry of list.slice(0, maxCommits)) {
    if (!entry.sha) continue;
    try {
      const res = await fetch(`${API}/repos/${fullName}/commits/${entry.sha}`, {
        headers: { ...GH_HEADERS, Authorization: `token ${token}` },
        signal: AbortSignal.timeout(TIMEOUT_MS),
      });
      if (!res.ok) continue;
      // GitHub returns each file's patch without a diff header; keep the path,
      // which the history scan needs to tell test scaffolding from shipped code.
      const detail = (await res.json()) as { files?: { filename?: string; patch?: string }[] };
      const patch = (detail.files ?? []).filter((file) => file.patch)
        .map((file) => typeof file.filename === "string"
          ? `diff --git a/${file.filename} b/${file.filename}\n${file.patch}` : file.patch).join("\n");
      if (!patch) continue;
      // GitHub omits a file's patch when its diff is too large and lists at
      // most 300 files; such a commit was not read in full (migration 109).
      const files = detail.files ?? [];
      out.push({
        complete: files.length < 300 && files.every((file) => typeof file.patch === "string"),
        sha: entry.sha,
        message: entry.commit?.message?.split("\n")[0] ?? "",
        patch,
        date: entry.commit?.author?.date ?? "",
      });
    } catch {
      // One unreadable commit must not cost us the rest of the window.
      continue;
    }
  }

  return out;
}

export interface PullRequestFiles {
  /** Readable files after the change. */
  files: { path: string; content: string }[];
  /** Number of entries GitHub returned on the bounded first page. */
  listed: number;
  /** True only when every listed change was readable and no page/file was omitted. */
  complete: boolean;
  coverage: string;
}

/** Names of files a pull request adds or modifies (first page, up to 100).
 * `complete` is false when GitHub has more pages or files were deleted. */
export async function listPullRequestFileNames(
  token: string,
  fullName: string,
  number: number,
): Promise<{ paths: string[]; complete: boolean }> {
  const res = await fetch(`${API}/repos/${fullName}/pulls/${number}/files?per_page=100`, {
    headers: { ...GH_HEADERS, Authorization: `token ${token}` },
    signal: AbortSignal.timeout(TIMEOUT_MS),
  });
  if (!res.ok) throw new Error(`GitHub PR files HTTP ${res.status}`);
  const json = (await res.json()) as Array<{ filename?: string; status?: string }>;
  const paths = json.filter((f) => f.filename && f.status !== "removed").map((f) => f.filename as string);
  const paginated = /(?:^|,)\s*<[^>]+>;\s*rel="next"/.test(res.headers.get("link") ?? "");
  return { paths, complete: !paginated && paths.length === json.length };
}

/** Files a pull request touches, with their content AFTER the change.
 *
 * The check is deliberately bounded. A partial diff can still prove a concrete
 * problem, but it can never produce a green conclusion.
 */
export async function listPullRequestFiles(
  token: string,
  fullName: string,
  number: number,
  headSha: string,
  maxFiles = 24,
): Promise<PullRequestFiles> {
  const res = await fetch(`${API}/repos/${fullName}/pulls/${number}/files?per_page=100`, {
    headers: { ...GH_HEADERS, Authorization: `token ${token}` },
    signal: AbortSignal.timeout(TIMEOUT_MS),
  });
  if (!res.ok) throw new Error(`GitHub PR files HTTP ${res.status}`);

  const json = (await res.json()) as Array<{ filename?: string; status?: string }>;

  const candidates = json.filter((f) => f.filename && f.status !== "removed");
  const paths = candidates
    .map((f) => f.filename as string)
    .slice(0, maxFiles);

  const files: { path: string; content: string }[] = [];
  for (let offset = 0; offset < paths.length; offset += 6) {
    const batch = paths.slice(offset, offset + 6);
    const reads = await Promise.all(batch.map(async (path) => ({
      path,
      // At the PR's head sha, not the default branch: we must judge the code as
      // proposed, not as it currently is on main.
      content: await getFile(token, fullName, path, headSha).catch(() => null),
    })));
    files.push(...reads.filter((file): file is { path: string; content: string } => file.content !== null));
  }
  const removed = json.filter((file) => file.filename && file.status === "removed").length;
  const paginated = /(?:^|,)\s*<[^>]+>;\s*rel="next"/.test(res.headers.get("link") ?? "");
  const omitted = Math.max(0, candidates.length - paths.length);
  const unread = paths.length - files.length;
  const complete = !paginated && removed === 0 && omitted === 0 && unread === 0;
  const reasons = [
    paginated ? "more than the first GitHub page changed" : null,
    removed ? `${removed} deleted file${removed === 1 ? " was" : "s were"} not readable at the head commit` : null,
    omitted ? `${omitted} file${omitted === 1 ? " was" : "s were"} beyond the ${maxFiles}-file review budget` : null,
    unread ? `${unread} file${unread === 1 ? " could" : "s could"} not be read` : null,
  ].filter(Boolean);
  return {
    files,
    listed: json.length,
    complete,
    coverage: complete && json.length === 0 ? "This pull request changes no files." : complete ? `All ${json.length} changed file${json.length === 1 ? " was" : "s were"} readable.` : `Partial diff: ${reasons.join("; ")}.`,
  };
}

/**
 * Posts a check run on a commit.
 *
 * `neutral` rather than `failure` for a warning, so a merge is never blocked by
 * something we are not confident about. A conclusion of `failure` is reserved
 * for a finding we would defend to the author's face.
 */
export async function createCheckRun(
  token: string,
  fullName: string,
  headSha: string,
  conclusion: "success" | "neutral" | "failure",
  title: string,
  summary: string,
  externalId: string,
): Promise<void> {
  if (!externalId || externalId.length > 255) throw new Error("Invalid GitHub check external id");
  const list = await fetch(
    `${API}/repos/${fullName}/commits/${encodeURIComponent(headSha)}/check-runs?check_name=ShipLock&filter=latest&per_page=100`,
    { headers: { ...GH_HEADERS, Authorization: `token ${token}` }, signal: AbortSignal.timeout(TIMEOUT_MS) },
  );
  if (!list.ok) throw new Error(`GitHub list check runs HTTP ${list.status}`);
  const listed = (await list.json()) as { check_runs?: Array<{ id?: number; external_id?: string }> };
  const existing = (listed.check_runs ?? []).find((run) => run.external_id === externalId && Number.isSafeInteger(run.id));
  const body = {
    name: "ShipLock",
    status: "completed",
    conclusion,
    completed_at: new Date().toISOString(),
    external_id: externalId,
    output: { title, summary: summary.slice(0, 65_000) },
  };
  if (existing?.id) {
    await ghWrite(token, `/repos/${fullName}/check-runs/${existing.id}`, "PATCH", body);
  } else {
    await ghWrite(token, `/repos/${fullName}/check-runs`, "POST", { ...body, head_sha: headSha });
  }
}
