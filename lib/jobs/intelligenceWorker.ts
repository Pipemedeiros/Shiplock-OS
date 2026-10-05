import { z } from "zod";
import { getSupabaseAdmin } from "@/lib/supabase";
import { createIntelligenceTask } from "@/lib/intelligence/tasks";
import { getBranchSha, getInstallationToken, listPullRequestFileNames, listTree } from "@/lib/deep/github";
import { claimJob, executeClaimedJob, PermanentJobError, type ClaimedJob } from "./queue";

// Scheduled customer-intelligence scans (10B-2c, migration 077). The job holds
// identity only; this worker re-reads the approval, repository, and
// installation, picks at most 16 files, and creates a task for the customer's
// approved host. It never calls or funds a model. The task expires within a
// day; an unanswered task is "AI check pending", never clean.

const MAX_PATHS = 16;
const TASK_MINUTES = 23 * 60;
const IGNORED = /(^|\/)(node_modules|\.next|dist|build|vendor|__tests__)\//;
const TEST_FILE = /\.(test|spec)\.[cm]?[jt]sx?$/;
const MIDDLEWARE = /^(src\/)?(middleware|proxy)\.[cm]?[jt]s$/;
const ROUTE = /(^|\/)app\/(.+\/)?route\.[cm]?[jt]sx?$|(^|\/)pages\/api\/.+\.[cm]?[jt]sx?$/;
const CODE = /\.([cm]?[jt]sx?|sql)$/;

/** Route handlers and middleware a deep scan may cover. */
export function deepScanCandidates(paths: string[]): string[] {
  return paths.filter((path) => !IGNORED.test(path) && !TEST_FILE.test(path) && (MIDDLEWARE.test(path) || ROUTE.test(path)));
}

/** Middleware first, then route handlers in path order. Past 16, a weekly
 * rotation moves the window so every handler is reached over time. */
export function pickDeepScanPaths(paths: string[], rotation: number): string[] {
  const candidates = deepScanCandidates(paths);
  const middleware = candidates.filter((path) => MIDDLEWARE.test(path)).sort();
  const routes = candidates.filter((path) => !MIDDLEWARE.test(path)).sort();
  const room = MAX_PATHS - middleware.length;
  if (routes.length <= room) return [...middleware, ...routes];
  const start = (rotation * room) % routes.length;
  return [...middleware, ...[...routes, ...routes].slice(start, start + room)];
}

export function pickPullRequestPaths(paths: string[]): string[] {
  return paths.filter((path) => CODE.test(path) && !IGNORED.test(path)).slice(0, MAX_PATHS);
}

const profileSchema = z.object({ github_installation_id: z.number().int().positive() });
const repositorySchema = z.object({ full_name: z.string().regex(/^[\w.-]+\/[\w.-]+$/), selected: z.literal(true), default_branch: z.string().min(1) });
const contextSchema = z.object({ user_id: z.uuid(), repository_id: z.uuid(), scan: z.enum(["deep", "pr"]),
  pull_request_number: z.number().int().positive().nullable(), head_sha: z.string().regex(/^[a-f0-9]{40}$/).nullable() });
const connectionSchema = z.object({ host: z.enum(["claude-code", "codex", "chatgpt", "api"]), revoked_at: z.string().nullable(),
  run_token_budget: z.number().int().positive() });

const RULES = "Cite exact lines with each file's sourceHash. Propose only mechanical edits; anything that depends on "
  + "who owns data, authorization, or business policy is needs_human with citations and no edits. If you cannot "
  + "finish, answer unavailable with a reason; never report clean for what you did not read.";

export async function executeIntelligenceJob(job: ClaimedJob): Promise<void> {
  if (job.kind !== "intelligence" || !job.repository_id || job.audit_run_id) {
    throw new PermanentJobError("Invalid intelligence scan context");
  }
  const admin = getSupabaseAdmin();
  const [profileRead, repositoryRead, contextRead, connectionRead] = await Promise.all([
    admin.from("user_profiles").select("github_installation_id").eq("id", job.user_id).maybeSingle(),
    admin.from("repositories").select("full_name, selected, default_branch").eq("id", job.repository_id).eq("user_id", job.user_id).maybeSingle(),
    admin.from("intelligence_scan_jobs").select("user_id, repository_id, scan, pull_request_number, head_sha").eq("job_id", job.id).maybeSingle(),
    admin.from("intelligence_connections").select("host, revoked_at, run_token_budget").eq("user_id", job.user_id).maybeSingle(),
  ]);
  if (profileRead.error || repositoryRead.error || contextRead.error || connectionRead.error) {
    throw new Error("Intelligence scan context could not be read");
  }
  const connection = connectionSchema.safeParse(connectionRead.data);
  // Revoked since admission: the customer withdrew consent, so do nothing. A
  // retired API-key approval ("api") is not consent for any host: ShipLock
  // runs no model (Felipe, 2026-10-01), and only the customer's agent answers.
  if (!connection.success || connection.data.revoked_at || connection.data.host === "api") return;
  const host = connection.data.host;
  const profile = profileSchema.safeParse(profileRead.data);
  const repository = repositorySchema.safeParse(repositoryRead.data);
  const context = contextSchema.safeParse(contextRead.data);
  if (!profile.success || !repository.success || !context.success
    || context.data.user_id !== job.user_id || context.data.repository_id !== job.repository_id) {
    throw new PermanentJobError("Intelligence scan context changed");
  }

  const token = await getInstallationToken(profile.data.github_installation_id);
  const fullName = repository.data.full_name;
  const budget = `Stay within ${connection.data.run_token_budget} tokens for this task.`;
  let commit: string, paths: string[], instruction: string;
  if (context.data.scan === "deep") {
    commit = await getBranchSha(token, fullName, repository.data.default_branch);
    const tree = await listTree(token, fullName, commit);
    const candidates = tree.map((entry) => entry.path);
    paths = pickDeepScanPaths(candidates, Math.floor(Date.now() / (7 * 86_400_000)));
    const total = deepScanCandidates(candidates).length;
    instruction = `Weekly deep review of ${fullName} at ${commit.slice(0, 12)}: ${paths.length} of ${total} route handlers `
      + `and middleware. Look for missing authentication or authorization, cross-tenant data access, unvalidated input `
      + `reaching queries or redirects, and secrets or internals exposed in responses. ${RULES} ${budget}`;
  } else {
    commit = context.data.head_sha!;
    const changed = await listPullRequestFileNames(token, fullName, context.data.pull_request_number!);
    paths = pickPullRequestPaths(changed.paths);
    instruction = `Review pull request #${context.data.pull_request_number} of ${fullName} at ${commit.slice(0, 12)}: `
      + `${paths.length} changed code files${changed.complete ? "" : " (the change list was partial)"}. Look for security `
      + `regressions the change introduces: weakened or missing auth checks, new data exposure, unsafe input handling. `
      + `${RULES} ${budget}`;
  }
  if (paths.length === 0) return;

  try {
    await createIntelligenceTask({ userId: job.user_id, repositoryId: job.repository_id, commit,
      host, instruction, paths, minutes: TASK_MINUTES, key: `job:${job.id}` });
  } catch (error) {
    const code = error instanceof Error ? error.message : "";
    // Revoked since admission, or the customer's monthly limit is reached.
    if (code === "intelligence_not_approved" || code === "intelligence_budget_exhausted") return;
    if (code === "repository_unavailable") throw new PermanentJobError("Repository no longer available");
    throw error;
  }
}

export async function runNextIntelligenceJob(): Promise<boolean> {
  const job = await claimJob("intelligence");
  if (!job) return false;
  await executeClaimedJob(job, [executeIntelligenceJob]);
  return true;
}
