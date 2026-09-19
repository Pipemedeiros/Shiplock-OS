import { z } from "zod";
import { getSupabaseAdmin } from "@/lib/supabase";
import { validateSupabaseUrl } from "@/lib/sanitize";
import { providerConnectionFingerprint } from "./providerRepositoryMap";
import { DirectRepositoryConfirmation } from "./databaseRepositoryBinding";
import { bindingDate, bindingNumericId, bindingRepositorySchema, loadDatabaseBindingIdentity } from "./databaseBindingIdentity";

export const SupabaseBindingCollector = z.enum(["supabase-management", "supabase-scan"]);
type Collector = z.infer<typeof SupabaseBindingCollector>;
const projectRef = z.string().min(1).max(63).regex(/^[a-z0-9-]+$/);
const endpointUrl = z.string().regex(/^https:\/\/[a-z0-9-]+\.supabase\.co$/);
const ciphertext = z.string().refine((value) => value.trim().length > 0);
const managementProfile = z.object({ supabase_mgmt_token_encrypted: ciphertext, supabase_mgmt_project_ref: projectRef });
const endpointProfile = z.object({ monitored_anon_key_encrypted: ciphertext, monitored_project_url: z.string() });
export const SupabaseRepositoryConfirmation = DirectRepositoryConfirmation.extend({
  collector: SupabaseBindingCollector, expectedProjectRef: projectRef, expectedEndpointUrl: endpointUrl.nullable(),
}).refine((value) => value.collector === "supabase-management" ? value.expectedEndpointUrl === null
  : value.expectedEndpointUrl === `https://${value.expectedProjectRef}.supabase.co`);
const bindingSchema = z.object({
  user_id: z.uuid(), repository_id: z.uuid(), collector: SupabaseBindingCollector, project_ref: projectRef, endpoint_url: endpointUrl.nullable(),
  connection_fingerprint: z.string().regex(/^[a-f0-9]{64}$/), github_installation_id: bindingNumericId,
  github_connected_at: bindingDate, repository_full_name: z.string(), github_repo_id: bindingNumericId.nullable(),
  confirmation_method: z.literal("customer_confirmed"), confirmed_at: bindingDate,
}).refine((value) => value.collector === "supabase-management" ? value.endpoint_url === null
  : value.endpoint_url === `https://${value.project_ref}.supabase.co`);
interface Context {
  collector: Collector; projectRef: string; endpointUrl: string | null; connectionFingerprint: string;
  installationId: string; githubConnectedAt: string; repositories: z.infer<typeof bindingRepositorySchema>[];
}

/** Each transport reads only its own configured credential/project. Matching
 * project names or fingerprints never authorizes borrowing another transport. */
async function currentContext(userId: string, collector: Collector): Promise<Context | null> {
  const columns = collector === "supabase-management" ? "supabase_mgmt_token_encrypted, supabase_mgmt_project_ref"
    : "monitored_anon_key_encrypted, monitored_project_url";
  const identity = await loadDatabaseBindingIdentity(userId, columns);
  if (!identity) return null;
  let credential: string, ref: string, endpoint: string | null = null;
  if (collector === "supabase-management") {
    const profile = managementProfile.safeParse(identity.profile);
    if (!profile.success) return null;
    credential = profile.data.supabase_mgmt_token_encrypted; ref = profile.data.supabase_mgmt_project_ref;
  } else {
    const profile = endpointProfile.safeParse(identity.profile);
    if (!profile.success) return null;
    try {
      endpoint = validateSupabaseUrl(profile.data.monitored_project_url);
      ref = projectRef.parse(new URL(endpoint).hostname.split(".")[0]);
    } catch { return null; }
    credential = profile.data.monitored_anon_key_encrypted;
  }
  return { collector, projectRef: ref, endpointUrl: endpoint, connectionFingerprint: providerConnectionFingerprint(credential),
    installationId: identity.profile.github_installation_id, githubConnectedAt: identity.profile.github_connected_at, repositories: identity.repositories };
}
function rowFor(userId: string, context: Context, repository: Context["repositories"][number], at: string) {
  return { user_id: userId, repository_id: repository.id, collector: context.collector,
    project_ref: context.projectRef, endpoint_url: context.endpointUrl, connection_fingerprint: context.connectionFingerprint,
    github_installation_id: context.installationId, github_connected_at: context.githubConnectedAt,
    repository_full_name: repository.full_name, github_repo_id: repository.github_repo_id,
    confirmation_method: "customer_confirmed" as const, confirmed_at: at };
}
function sameContext(before: Context, after: Context | null, repository: Context["repositories"][number]) {
  const candidate = after?.repositories.find((item) => item.id === repository.id);
  return after !== null && candidate !== undefined && before.collector === after.collector && before.projectRef === after.projectRef &&
    before.endpointUrl === after.endpointUrl && before.connectionFingerprint === after.connectionFingerprint &&
    before.installationId === after.installationId && before.githubConnectedAt === after.githubConnectedAt &&
    repository.full_name === candidate.full_name && repository.github_repo_id === candidate.github_repo_id;
}

/** Customer-confirmed association only. No graph facts, provider requests,
 * decryption or customer data are used, and no graph joins are enabled. */
export async function getSupabaseRepositoryBindings(userId: string, collector: Collector) {
  const context = await currentContext(userId, collector);
  if (!context) return { available: false as const, collector, repositories: [], bindings: [] };
  const { data, error } = await getSupabaseAdmin().from("database_repository_bindings").select("*")
    .eq("user_id", userId).eq("collector", collector);
  if (error || !Array.isArray(data)) throw new Error("Binding read unavailable");
  const counts = new Map<string, number>();
  for (const row of data) if (row && typeof row.repository_id === "string") counts.set(row.repository_id, (counts.get(row.repository_id) ?? 0) + 1);
  const bindings: { repositoryId: string; method: "customer_confirmed"; confirmedAt: string }[] = [];
  for (const raw of data) {
    const row = bindingSchema.safeParse(raw);
    if (!row.success || counts.get(row.data.repository_id) !== 1 || Date.parse(row.data.confirmed_at) > Date.now() ||
        Date.parse(row.data.confirmed_at) < Date.parse(context.githubConnectedAt)) continue;
    const repository = context.repositories.find((candidate) => candidate.id === row.data.repository_id);
    if (!repository) continue;
    const expected = rowFor(userId, context, repository, row.data.confirmed_at);
    if (Object.entries(expected).some(([key, value]) => row.data[key as keyof typeof expected] !== value)) continue;
    bindings.push({ repositoryId: repository.id, method: "customer_confirmed", confirmedAt: row.data.confirmed_at });
  }
  return { available: true as const, collector, projectRef: context.projectRef, endpointUrl: context.endpointUrl,
    connectionFingerprint: context.connectionFingerprint, installationId: context.installationId, githubConnectedAt: context.githubConnectedAt,
    repositories: context.repositories.map((repository) => ({ id: repository.id, fullName: repository.full_name, githubRepoId: repository.github_repo_id })), bindings };
}

export async function changeSupabaseRepositoryBinding(userId: string, input: z.infer<typeof SupabaseRepositoryConfirmation>): Promise<"ok" | "stale"> {
  const context = await currentContext(userId, input.collector);
  const repository = context?.repositories.find((candidate) => candidate.id === input.repositoryId);
  if (!context || !repository || input.expectedProjectRef !== context.projectRef || input.expectedEndpointUrl !== context.endpointUrl ||
      input.expectedConnectionFingerprint !== context.connectionFingerprint || input.expectedInstallationId !== context.installationId ||
      input.expectedGithubConnectedAt !== context.githubConnectedAt || input.expectedRepositoryFullName !== repository.full_name ||
      input.expectedGithubRepositoryId !== repository.github_repo_id) return "stale";
  const admin = getSupabaseAdmin();
  if (input.action === "remove") {
    let query = admin.from("database_repository_bindings").delete().eq("user_id", userId).eq("repository_id", repository.id)
      .eq("collector", input.collector).eq("project_ref", context.projectRef).eq("connection_fingerprint", context.connectionFingerprint)
      .eq("github_installation_id", context.installationId).eq("github_connected_at", context.githubConnectedAt);
    query = context.endpointUrl === null ? query.is("endpoint_url", null) : query.eq("endpoint_url", context.endpointUrl);
    const { data, error } = await query.select("repository_id");
    if (error || !Array.isArray(data) || data.some((row) => row?.repository_id !== repository.id)) throw new Error("Binding removal unavailable");
  } else {
    const expected = rowFor(userId, context, repository, new Date(Date.now()).toISOString());
    const { data, error } = await admin.from("database_repository_bindings")
      .upsert(expected, { onConflict: "user_id,collector,repository_id" }).select("*").single();
    const receipt = bindingSchema.safeParse(data);
    if (error || !receipt.success || Object.entries(expected).some(([key, value]) => receipt.data[key as keyof typeof expected] !== value)) {
      throw new Error("Binding persistence unavailable");
    }
  }
  return sameContext(context, await currentContext(userId, input.collector), repository) ? "ok" : "stale";
}
