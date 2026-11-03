import { createHash } from "node:crypto";
import { z } from "zod";
import { getSupabaseAdmin } from "@/lib/supabase";
import { createBranch, findOpenPullRequestForBranch, getBranchSha, getFileSha, getInstallationToken, listTree,
  openPullRequest, putFile } from "@/lib/deep/github";
import { matchHotPaths } from "@/lib/traffic/routeMatch";
import { buildRateLimitSuggestion } from "@/lib/traffic/rateLimitSuggestion";
import { openedOutcome, type RepairOutcome } from "./repairOutcome";

// One click, one PR for a customer-side rate limit (migration
// 093). The receipt names a route file; this re-derives the suggestion from
// the repository's current observed traffic (086) and its current tree, adds
// the single off-by-default helper file on a new branch cut from the default
// branch, and opens the PR. It never edits an existing file or writes to the
// default branch. ShipLock never merges or deploys.

const WINDOW_HOURS = 6; // the gateway log read covers the last six hours
const repositorySchema = z.object({ full_name: z.string(), default_branch: z.string().min(1), selected: z.boolean() });
const observationSchema = z.array(z.object({ path: z.string(), suspicious_requests: z.number().int().positive() }));
const sha = (s: string) => createHash("sha256").update(s).digest("hex");

/** Opens a pull request adding a rate limit to a route that observed traffic
 * hit hard. */
export async function openRateLimitPr(userId: string, findingId: string, repositoryId: string): Promise<RepairOutcome> {
  const routeFile = /^traffic:(\S+)$/.exec(findingId)?.[1];
  if (!routeFile) return { status: "failed", code: "finding_unavailable" };
  const admin = getSupabaseAdmin();
  const [repositoryRead, profileRead, observationsRead] = await Promise.all([
    admin.from("repositories").select("full_name, default_branch, selected").eq("id", repositoryId).eq("user_id", userId).maybeSingle(),
    admin.from("user_profiles").select("github_installation_id").eq("id", userId).maybeSingle(),
    admin.from("traffic_route_observations").select("path, suspicious_requests").eq("user_id", userId).eq("repository_id", repositoryId),
  ]);
  if (repositoryRead.error || profileRead.error || observationsRead.error) throw new Error("rate-limit context unreadable");
  const repository = repositorySchema.safeParse(repositoryRead.data);
  if (!repository.success || !repository.data.selected) return { status: "failed", code: "repository_unavailable" };
  const installationId = profileRead.data?.github_installation_id as number | null | undefined;
  if (!installationId) return { status: "failed", code: "repository_unavailable" };
  const observations = observationSchema.safeParse(observationsRead.data ?? []);
  if (!observations.success) throw new Error("traffic observations unreadable");

  const repo = repository.data.full_name;
  const base = repository.data.default_branch;
  const token = await getInstallationToken(installationId);
  const branch = `shiplock/rate-limit-${sha(`${userId}\0${repositoryId}\0${routeFile}`).slice(0, 20)}`;
  const recovered = await findOpenPullRequestForBranch(token, repo, branch);
  if (recovered) return openedOutcome(recovered);

  const files = (await listTree(token, repo, base)).map((entry) => entry.path);
  const hot = matchHotPaths(observations.data.map((o) => ({ path: o.path, suspiciousRequests: o.suspicious_requests })), files)
    .matched.find((route) => route.file === routeFile);
  if (!hot) return { status: "failed", code: "finding_unavailable" };
  const suggestion = buildRateLimitSuggestion(hot, files, { windowHours: WINDOW_HOURS });
  if (suggestion.kind === "refused") return { status: "failed", code: "no_changes" };

  const baseSha = await getBranchSha(token, repo, base);
  const exists = await getBranchSha(token, repo, branch).then(() => true).catch(() => false);
  if (!exists) await createBranch(token, repo, branch, baseSha);
  for (const file of suggestion.files) {
    // A retry after an uncertain outcome may find the helper already written.
    if (await getFileSha(token, repo, file.path, branch)) continue;
    await putFile(token, repo, file.path, branch, file.content, undefined, suggestion.title);
  }
  return openedOutcome(await openPullRequest(token, repo, branch, base, suggestion.title, suggestion.body));
}
