import { z } from "zod";
import { getSupabaseAdmin } from "@/lib/supabase";
import type { ReachabilityIndex } from "./reachability";
import type { GraphInput } from "./graph";

const repositoryName = z.string().regex(/^[\w.-]+\/[\w.-]+$/);
const installationId = z.union([
  z.string().regex(/^[1-9]\d*$/), z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
]).transform(String);
const profileSchema = z.object({ github_installation_id: installationId, github_connected_at: z.string() });
const selectedSchema = z.array(z.object({ id: z.string().min(1), full_name: repositoryName, default_branch: z.string().min(1) }));
const pathSchema = z.string().min(1).max(1024).refine((value) =>
  !value.startsWith("/") && !/[\x00-\x1f]/.test(value) && !value.split("/").includes(".."));
const snapshotSchema = z.object({
  repositoryFullName: repositoryName,
  installationId,
  ref: z.string().min(1),
  recordedAt: z.string(),
  // Current producer never establishes complete coverage. Do not trust an
  // invented 'complete' flag in stored JSON to enable negative conclusions.
  completeness: z.literal("partial"),
  filesAttempted: z.number().int().nonnegative().max(60),
  filesRead: z.number().int().positive().max(60),
  hasEntryPoints: z.boolean(),
  liveFiles: z.array(pathSchema).max(60),
  // Each consumer validates only the payload it actually uses.
  routes: z.unknown().optional(),
  dependencies: z.unknown().optional(),
}).refine((value) => value.filesRead <= value.filesAttempted && value.liveFiles.length <= value.filesRead);

function timestamp(value: string): number {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?(?:Z|[+-]\d{2}:\d{2})$/.test(value)) return NaN;
  return Date.parse(value);
}

export interface AdmittedRepositorySource {
  repositoryFullName: string;
  snapshot: z.infer<typeof snapshotSchema>;
}

/** Read-only identity admission; no provider/DB association is inferred. */
export async function loadSelectedRepositorySources(userId: string, now = Date.now()): Promise<Map<string, AdmittedRepositorySource>> {
  const result = new Map<string, AdmittedRepositorySource>();
  try {
    const admin = getSupabaseAdmin();
    const [profileRead, selectedRead, sourceRead] = await Promise.all([
      admin.from("user_profiles").select("github_installation_id, github_connected_at").eq("id", userId).maybeSingle(),
      admin.from("repositories").select("id, full_name, default_branch").eq("user_id", userId).eq("selected", true),
      admin.from("graph_facts").select("facts").eq("user_id", userId).eq("collector", "source").maybeSingle(),
    ]);
    if (profileRead.error || selectedRead.error || sourceRead.error) throw new Error("Scoped source read unavailable");
    const profile = profileSchema.safeParse(profileRead.data);
    const selected = selectedSchema.safeParse(selectedRead.data);
    if (!profile.success || !selected.success) return result;
    const connectedAt = timestamp(profile.data.github_connected_at);
    if (!Number.isFinite(connectedAt) || connectedAt > now) return result;
    const raw: unknown = sourceRead.data?.facts?.repositories;
    if (!Array.isArray(raw) || raw.length > 10) return result;

    // Count raw names before parsing: even a malformed duplicate must not
    // allow us to choose whichever apparently valid observation is convenient.
    const snapshotNames = new Map<string, number>();
    for (const value of raw) {
      if (value && typeof value.repositoryFullName === "string") {
        const name = value.repositoryFullName.toLowerCase();
        snapshotNames.set(name, (snapshotNames.get(name) ?? 0) + 1);
      }
    }
    const selectedByName = new Map<string, typeof selected.data[number]>();
    const ambiguous = new Set<string>();
    const idCounts = new Map<string, number>();
    for (const repository of selected.data) {
      const name = repository.full_name.toLowerCase();
      if (selectedByName.has(name)) ambiguous.add(name);
      selectedByName.set(name, repository);
      idCounts.set(repository.id, (idCounts.get(repository.id) ?? 0) + 1);
    }
    for (const value of raw) {
      const parsed = snapshotSchema.safeParse(value);
      if (!parsed.success) continue;
      const snapshot = parsed.data;
      const name = snapshot.repositoryFullName.toLowerCase();
      const repository = selectedByName.get(name);
      const recordedAt = timestamp(snapshot.recordedAt);
      if (!repository || ambiguous.has(name) || idCounts.get(repository.id) !== 1 || snapshotNames.get(name) !== 1 ||
          snapshot.installationId !== profile.data.github_installation_id || snapshot.ref !== repository.default_branch ||
          !Number.isFinite(recordedAt) || recordedAt < connectedAt || recordedAt > now) continue;
      result.set(repository.id, { repositoryFullName: name, snapshot });
    }
  } catch {
    // No raw database error, snapshot, identity or credential enters logs.
    console.error("[source] Selected-repository evidence unavailable; admission remains unknown");
  }
  return result;
}

export async function loadRepositoryReachability(userId: string, now = Date.now()): Promise<ReachabilityIndex> {
  const repositoryIndices = new Map<string, ReachabilityIndex>();
  for (const { repositoryFullName, snapshot } of (await loadSelectedRepositorySources(userId, now)).values()) {
    repositoryIndices.set(repositoryFullName, {
      liveFiles: new Set(snapshot.liveFiles), hasEntryPoints: snapshot.hasEntryPoints,
      exposedTables: new Set(), coverage: "partial",
    });
  }
  return { liveFiles: new Set(), exposedTables: new Set(), hasEntryPoints: false, repositoryIndices };
}

const dependenciesSchema = z.array(z.object({
  name: z.string().min(1).max(214).regex(/^(?:@[a-z0-9._-]+\/)?[a-z0-9._-]+$/i),
  version: z.string().min(1).max(256).regex(/^[^\x00-\x1f]+$/),
})).max(5000).refine((items) => new Set(items.map((item) => item.name)).size === items.length);

/** Partial inventories can add findings but cannot retire absent advisories. */
export async function loadRepositoryDependencies(userId: string) {
  const inventories = [];
  for (const [repositoryId, source] of await loadSelectedRepositorySources(userId)) {
    const dependencies = dependenciesSchema.safeParse(source.snapshot.dependencies);
    if (dependencies.success) inventories.push({ repositoryId, repositoryFullName: source.repositoryFullName,
      dependencies: dependencies.data, completeness: "partial" as const });
  }
  return inventories;
}

const routeSchema = z.object({
  path: z.string().min(1).max(1024).regex(/^\/[^\x00-\x1f]*$/),
  file: pathSchema,
  methods: z.array(z.enum(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"])).min(1).max(7),
  tables: z.array(z.string().min(1).max(256).regex(/^[^\x00-\x1f]+$/)).max(60),
  authenticated: z.boolean(), machineGated: z.boolean(), usesServiceRole: z.boolean(), ownershipFiltered: z.boolean(),
  identityReadable: z.boolean(), ownershipReadable: z.boolean(), dataReadable: z.boolean(),
  machineGateReadable: z.boolean(), serviceRoleReadable: z.boolean(),
  identityGap: z.string().max(4096).nullable(), ownershipGap: z.string().max(4096).nullable(),
  dataGap: z.string().max(4096).nullable(), machineGateGap: z.string().max(4096).nullable(),
  via: z.array(pathSchema).max(60),
});
const routesSchema = z.array(routeSchema).max(60).refine((routes) => new Set(routes.map((route) => route.path)).size === routes.length);

/** No account-wide DB/traffic/runtime facts may ride along with scoped source. */
export async function loadRepositoryGraphSource(userId: string, repositoryId: string): Promise<GraphInput> {
  const admitted = (await loadSelectedRepositorySources(userId)).get(repositoryId);
  const routes = routesSchema.safeParse(admitted?.snapshot.routes);
  if (!admitted || !routes.success) return { repositoryId, sourceCoverage: "unknown", correlationScope: "source-only" };
  return { repositoryId, sourceCoverage: "partial", correlationScope: "source-only", routes: routes.data };
}
