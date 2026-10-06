import { getBranchSha } from "./github";

// Read-only: the commit an audit reads. Kept out of github.ts, whose write
// paths are a pinned, reviewed boundary (receipted-pr-writes).
const API = "https://api.github.com";
const HEADERS = { Accept: "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28" };

/**
 * The head of the default branch. Tries the stored branch name first; if
 * GitHub no longer has it (a renamed default branch), asks GitHub for the
 * current default branch once, so the audit follows it instead of failing.
 */
export async function getHeadCommit(token: string, fullName: string, storedBranch: string): Promise<string> {
  try {
    return await getBranchSha(token, fullName, storedBranch);
  } catch (first) {
    const res = await fetch(`${API}/repos/${fullName}`, {
      headers: { ...HEADERS, Authorization: `token ${token}` },
      signal: AbortSignal.timeout(12_000),
    });
    if (!res.ok) throw first;
    const branch = ((await res.json()) as { default_branch?: string }).default_branch;
    if (!branch || branch === storedBranch) throw first;
    return getBranchSha(token, fullName, branch);
  }
}
