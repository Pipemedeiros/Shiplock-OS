import { decrypt } from "@/lib/crypto";
import { listProjects, listProjectEnv } from "./vercel";
import { auditEnv, type EnvFinding } from "./envaudit";
import type { RuntimeEnvFact } from "@/lib/graph/graph";
import type { ProviderCommit } from "@/lib/monitoring/registry";
import { syncVercelRepositoryLinks } from "./providerRepositoryMap";

const MAX_PROJECTS = 20;

// Full env audit for a connected Vercel account: list projects, read each
// project's env (read-only), audit, then hand the findings and runtime facts to
// the monitor worker's fenced commit, which inserts only NEW findings into
// deep_findings (source='vercel'). Never persists or logs any env VALUE —
// findings hold the key and reason only.
export async function runVercelEnvAudit(
  userId: string,
  encryptedToken: string,
  /** Epoch read in the same profile row as `encryptedToken` (migration 067). */
  connectionEpoch: string,
  teamId: string | null,
  { signal, commit }: { signal?: AbortSignal; commit: ProviderCommit },
): Promise<{
  total: number;
  newCount: number;
  findings: EnvFinding[];
  newFindings: EnvFinding[];
}> {
  const accessToken = decrypt(encryptedToken);

  const projects = (await listProjects(accessToken, teamId, signal)).slice(0, MAX_PROJECTS);
  // Every write below is skipped once the collector has been cancelled.
  signal?.throwIfAborted();
  let repositoryByProject = new Map<string, string>();
  try {
    repositoryByProject = await syncVercelRepositoryLinks(userId, projects, connectionEpoch);
  } catch (err) {
    // Provider-only checks may still run, but repository attribution fails
    // closed. A persistence/read failure never becomes an in-memory mapping.
    console.error(
      "[vercel] provider repository mapping failed:",
      err instanceof Error ? err.message : "unknown error",
    );
  }
  const all: EnvFinding[] = [];
  const graphEnvVars: RuntimeEnvFact[] = [];
  let reachedAnyProject = false;

  for (const project of projects) {
    let envs;
    try {
      envs = await listProjectEnv(accessToken, project.id, teamId, signal);
    } catch {
      // Cancellation ends the pass; it is not one unreadable project.
      signal?.throwIfAborted();
      continue; // a single unreadable project shouldn't fail the whole pass
    }
    reachedAnyProject = true;
    all.push(...auditEnv(project.name, envs));

    // Names, scopes and project identity only. A value never enters the graph, and never enters
    // a log: "ShipLock never reads your users' data" covers their secrets too.
    for (const env of envs) {
      graphEnvVars.push({
        key: env.key,
        target: Array.isArray(env.target) ? env.target : [],
        provider: "vercel",
        projectId: project.id,
        connectionFingerprint: connectionEpoch,
        ...(repositoryByProject.get(project.id)
          ? { repositoryId: repositoryByProject.get(project.id) }
          : {}),
      });
    }
  }

  if (projects.length > 0 && !reachedAnyProject) {
    throw new Error("No Vercel project environment was readable");
  }

  // The graph half. Findings above are what Vercel alone can say; these facts
  // retain provider project and installation provenance. Only successfully
  // persisted, explicit provider Git links supply a repository association.
  //
  // providersRead is written only when we actually reached a project. An empty
  // list after a failed read would tell the reasoner we looked and found
  // nothing, which is the `rulesRead` mistake on a new surface.
  signal?.throwIfAborted();
  // Runtime facts and env findings commit together under the monitor job's
  // lease and this connection epoch (3F-C2c). Vercel findings have never been
  // archived here, so the commit does not retire either.
  const created = await commit({
    transport: "vercel", identity: connectionEpoch,
    ...(reachedAnyProject ? { facts: { providersRead: ["vercel"], envVars: graphEnvVars } } : {}),
    findings: all, retire: false,
  });
  return { total: all.length, newCount: created.length, findings: all, newFindings: created as EnvFinding[] };
}
