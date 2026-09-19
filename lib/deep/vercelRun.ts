import { getSupabaseAdmin } from "@/lib/supabase";
import { decrypt } from "@/lib/crypto";
import { saveFacts } from "@/lib/graph/graphRun";
import { listProjects, listProjectEnv } from "./vercel";
import { auditEnv, type EnvFinding } from "./envaudit";
import type { RuntimeEnvFact } from "@/lib/graph/graph";
import { syncVercelRepositoryLinks, providerConnectionFingerprint } from "./providerRepositoryMap";

const MAX_PROJECTS = 20;

// Full env audit for a connected Vercel account: list projects, read each
// project's env (read-only), audit, then persist only NEW findings into the
// shared deep_findings table (source='vercel'). Same only-new contract as the
// GitHub A03 pass. Never persists or logs any env VALUE — findings hold the key
// and reason only.
export async function runVercelEnvAudit(
  userId: string,
  encryptedToken: string,
  teamId: string | null
): Promise<{ total: number; newCount: number; findings: EnvFinding[] }> {
  const admin = getSupabaseAdmin();
  const accessToken = decrypt(encryptedToken);

  const projects = (await listProjects(accessToken, teamId)).slice(0, MAX_PROJECTS);
  let repositoryByProject = new Map<string, string>();
  try {
    repositoryByProject = await syncVercelRepositoryLinks(userId, projects, encryptedToken);
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
      envs = await listProjectEnv(accessToken, project.id, teamId);
    } catch {
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
        connectionFingerprint: providerConnectionFingerprint(encryptedToken),
        ...(repositoryByProject.get(project.id)
          ? { repositoryId: repositoryByProject.get(project.id) }
          : {}),
      });
    }
  }

  // The graph half. Findings above are what Vercel alone can say; these facts
  // retain provider project and installation provenance. Only successfully
  // persisted, explicit provider Git links supply a repository association.
  //
  // providersRead is written only when we actually reached a project. An empty
  // list after a failed read would tell the reasoner we looked and found
  // nothing, which is the `rulesRead` mistake on a new surface.
  if (reachedAnyProject) {
    await saveFacts(
      userId,
      "runtime",
      { providersRead: ["vercel"], envVars: graphEnvVars },
      { merge: true },
    );
  }

  const { data: existing } = await admin
    .from("deep_findings")
    .select("finding_id")
    .eq("user_id", userId)
    .eq("source", "vercel")
    .is("archived_at", null);
  const activeIds = new Set((existing ?? []).map((r) => r.finding_id as string));

  const fresh = all.filter((f) => !activeIds.has(f.id));
  if (fresh.length > 0) {
    await admin.from("deep_findings").insert(
      fresh.map((f) => ({
        user_id: userId, source: "vercel", finding_id: f.id,
        severity: f.severity, title: f.title, consequence: f.consequence,
        package_name: null, version: null, vuln_id: null, cve_id: null,
      }))
    );
  }
  return { total: all.length, newCount: fresh.length, findings: all };
}
