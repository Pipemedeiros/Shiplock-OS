import { createSign } from "crypto";
import { env } from "@/lib/env";
import type { Severity } from "@/lib/types";
import type { Dep, OsvVuln } from "./githubScan";
import { fixedVersionFromOsv } from "./githubFix";

// GitHub App API access. READ-ONLY: the App requests only "Repository contents:
// read" + "Metadata: read" (see GITHUB_APP_SETUP.md). This module never writes
// to a repo. All functions throw a clear error at call time if the App isn't
// configured yet — same optional-env pattern as lib/deep/vercel.ts.
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
export async function getInstallationToken(installationId: string | number): Promise<string> {
  const res = await fetch(`${API}/app/installations/${installationId}/access_tokens`, {
    method: "POST",
    headers: { ...GH_HEADERS, Authorization: `Bearer ${appJwt()}` },
    signal: AbortSignal.timeout(TIMEOUT_MS),
  });
  if (!res.ok) throw new Error(`GitHub installation token HTTP ${res.status}`);
  const json = (await res.json()) as { token: string };
  return json.token;
}

export interface Repo {
  fullName: string; // owner/name
  defaultBranch: string;
}

export async function listRepos(token: string): Promise<Repo[]> {
  const res = await fetch(`${API}/installation/repositories?per_page=100`, {
    headers: { ...GH_HEADERS, Authorization: `token ${token}` },
    signal: AbortSignal.timeout(TIMEOUT_MS),
  });
  if (!res.ok) throw new Error(`GitHub list repos HTTP ${res.status}`);
  const json = (await res.json()) as { repositories?: Array<{ full_name: string; default_branch: string }> };
  return (json.repositories ?? []).map((r) => ({ fullName: r.full_name, defaultBranch: r.default_branch }));
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

export async function getFile(token: string, fullName: string, path: string, branch: string): Promise<string | null> {
  const res = await fetch(`${API}/repos/${fullName}/contents/${path.split("/").map(encodeURIComponent).join("/")}?ref=${encodeURIComponent(branch)}`, {
    headers: { ...GH_HEADERS, Authorization: `token ${token}` },
    signal: AbortSignal.timeout(TIMEOUT_MS),
  });
  if (!res.ok) return null;
  const json = (await res.json()) as { content?: string; encoding?: string };
  if (json.encoding !== "base64" || !json.content) return null;
  return Buffer.from(json.content, "base64").toString("utf8");
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

  const batchRes = await fetch("https://api.osv.dev/v1/querybatch", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      queries: deps.map((d) => ({ package: { name: d.name, ecosystem: "npm" }, version: d.version })),
    }),
    signal: AbortSignal.timeout(TIMEOUT_MS),
  });
  if (!batchRes.ok) throw new Error(`OSV querybatch HTTP ${batchRes.status}`);
  const batch = (await batchRes.json()) as { results?: Array<{ vulns?: Array<{ id: string }> }> };

  const out: { dep: Dep; vulns: OsvVuln[] }[] = [];
  const results = batch.results ?? [];
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
// write permissions (see GITHUB_APP_SETUP.md).

async function ghWrite(token: string, path: string, method: string, body: unknown) {
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
    `${API}/repos/${fullName}/contents/${path.split("/").map(encodeURIComponent).join("/")}?ref=${encodeURIComponent(branch)}`,
    { headers: { ...GH_HEADERS, Authorization: `token ${token}` }, signal: AbortSignal.timeout(TIMEOUT_MS) }
  );
  if (!res.ok) return null;
  const json = (await res.json()) as { sha?: string };
  return json.sha ?? null;
}

export async function putFile(
  token: string, fullName: string, path: string, branch: string, contentUtf8: string, sha: string, message: string
): Promise<void> {
  await ghWrite(token, `/repos/${fullName}/contents/${path.split("/").map(encodeURIComponent).join("/")}`, "PUT", {
    message,
    content: Buffer.from(contentUtf8, "utf8").toString("base64"),
    sha,
    branch,
  });
}

export async function openPullRequest(
  token: string, fullName: string, head: string, base: string, title: string, body: string
): Promise<string> {
  const pr = (await ghWrite(token, `/repos/${fullName}/pulls`, "POST", { title, head, base, body })) as {
    html_url?: string;
  };
  if (!pr.html_url) throw new Error("GitHub PR missing html_url");
  return pr.html_url;
}
