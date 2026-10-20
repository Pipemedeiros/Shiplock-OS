import { z } from "zod";

/**
 * "Is it live?" Hosts that deploy from GitHub (Vercel, Netlify, Render) report
 * each production deploy as a GitHub Deployment carrying its commit. The
 * newest one whose latest status is success is what visitors get; a newer one
 * that failed or is still running means the newest code has not shipped yet.
 * The distance from the default branch says how much code is not live, which
 * the repository alone cannot know (a fix merged is not a fix deployed).
 *
 * Read only, with the installation token the source job already holds. It
 * needs the App's deployments read permission; without it the read is
 * unreadable, and unreadable is never shown as current.
 */
const API = "https://api.github.com";
const TIMEOUT_MS = 10_000;
const HEADERS = { Accept: "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28" };
const MAX_DEPLOYS = 5;

const Sha = z.string().regex(/^[0-9a-f]{40}$/);
const Point = z.object({ sha: Sha, at: z.string().max(40) });
const STATES = ["success", "failure", "error", "in_progress", "queued", "pending", "inactive", "unknown"] as const;
export const productionDeploySchema = z.discriminatedUnion("state", [
  z.object({ state: z.literal("read"), environment: z.string().max(100), host: z.string().max(40).nullable(), headSha: Sha,
    live: Point.nullable(), latest: Point.extend({ state: z.enum(STATES) }), behindBy: z.number().int().nonnegative().nullable() }),
  z.object({ state: z.literal("none") }),
  z.object({ state: z.literal("unreadable"), why: z.string().max(300) }),
]);
export type ProductionDeploy = z.infer<typeof productionDeploySchema>;

type Deploy = { id: number; sha: string; environment: string; production_environment?: boolean; created_at: string; creator?: { login?: string } | null };
type Status = { state: string; created_at: string };

class Unreadable extends Error {}

async function get(token: string, path: string): Promise<unknown> {
  let res: Response;
  try {
    res = await fetch(`${API}${path}`, { headers: { ...HEADERS, Authorization: `token ${token}` }, signal: AbortSignal.timeout(TIMEOUT_MS) });
  } catch {
    throw new Unreadable("GitHub did not answer the deployments read.");
  }
  if (res.status === 403 || res.status === 404) throw new Unreadable("ShipLock's GitHub App has not been granted read access to deployments.");
  if (!res.ok) throw new Unreadable(`GitHub answered the deployments read with HTTP ${res.status}.`);
  return res.json();
}

const isProduction = (x: Deploy) => x.production_environment === true || /^production$/i.test(x.environment);
const hostOf = (login: string | undefined) => login?.replace(/\[bot\]$/, "").split(/[-_]/)[0]?.toLowerCase().slice(0, 40) || null;

/** Pure: the live and newest production deploy from deployments (newest first) and each one's latest status. */
export function summarizeDeploys(deploys: readonly Deploy[], statuses: ReadonlyMap<number, Status>) {
  const production = deploys.filter(isProduction).slice(0, MAX_DEPLOYS);
  const newest = production[0];
  if (!newest) return null;
  const stateOf = (x: Deploy) => {
    const state = statuses.get(x.id)?.state ?? "unknown";
    return (STATES as readonly string[]).includes(state) ? state as typeof STATES[number] : "unknown";
  };
  const live = production.find((x) => stateOf(x) === "success");
  return {
    environment: newest.environment, host: hostOf(newest.creator?.login),
    live: live ? { sha: live.sha, at: statuses.get(live.id)!.created_at } : null,
    latest: { sha: newest.sha, state: stateOf(newest), at: statuses.get(newest.id)?.created_at ?? newest.created_at },
  };
}

/** The production deploy of one repository against its default branch head. */
export async function readProductionDeploy(token: string, fullName: string, headSha: string): Promise<ProductionDeploy> {
  if (!Sha.safeParse(headSha).success) return { state: "unreadable", why: "The default branch head was not a commit." };
  try {
    const deploys = z.array(z.object({ id: z.number(), sha: Sha, environment: z.string(), production_environment: z.boolean().optional(),
      created_at: z.string(), creator: z.object({ login: z.string().optional() }).nullable().optional() }).loose())
      .parse(await get(token, `/repos/${fullName}/deployments?per_page=20`));
    const production = deploys.filter(isProduction).slice(0, MAX_DEPLOYS);
    if (production.length === 0) return { state: "none" };
    const statuses = new Map<number, Status>();
    // The first status listed is the newest.
    for (const x of production) {
      const list = z.array(z.object({ state: z.string(), created_at: z.string() }).loose())
        .parse(await get(token, `/repos/${fullName}/deployments/${x.id}/statuses?per_page=1`));
      if (list[0]) statuses.set(x.id, list[0]);
      if (list[0]?.state === "success") break;
    }
    const summary = summarizeDeploys(production, statuses)!;
    let behindBy: number | null = null;
    if (summary.live?.sha === headSha) behindBy = 0;
    else if (summary.live) {
      const compare = z.object({ status: z.string(), ahead_by: z.number().int().nonnegative() }).loose()
        .parse(await get(token, `/repos/${fullName}/compare/${summary.live.sha}...${headSha}`));
      behindBy = compare.status === "ahead" ? compare.ahead_by : null;
    }
    return { state: "read", ...summary, headSha, behindBy };
  } catch (err) {
    return { state: "unreadable", why: err instanceof Unreadable ? err.message : "GitHub's deployments answer could not be read." };
  }
}
