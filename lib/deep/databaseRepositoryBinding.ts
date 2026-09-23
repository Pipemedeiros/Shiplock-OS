import { z } from "zod";
import { getSupabaseAdmin } from "@/lib/supabase";
import { bindingDate as date, bindingNumericId as numericId, bindingRepositorySchema as repositorySchema,
  loadDatabaseBindingIdentity } from "./databaseBindingIdentity";

const profileSchema = z.object({ postgres_dsn_encrypted: z.string().refine((value) => value.trim().length > 0),
  postgres_connection_epoch: z.string().regex(/^[a-f0-9]{64}$/),
  postgres_display: z.string().nullable().optional(), github_installation_id: numericId, github_connected_at: date });
const bindingSchema = z.object({
  user_id: z.uuid(), repository_id: z.uuid(), collector: z.literal("postgres-direct"),
  connection_fingerprint: z.string().regex(/^[a-f0-9]{64}$/), github_installation_id: numericId,
  github_connected_at: date, repository_full_name: z.string(), github_repo_id: numericId.nullable(),
  confirmation_method: z.literal("customer_confirmed"), confirmed_at: date,
});
export const DirectRepositoryConfirmation = z.strictObject({
  action: z.enum(["confirm", "remove"]), confirmed: z.literal(true), repositoryId: z.uuid(),
  expectedConnectionFingerprint: z.string().regex(/^[a-f0-9]{64}$/), expectedInstallationId: z.string().regex(/^[1-9]\d*$/),
  expectedGithubConnectedAt: date, expectedRepositoryFullName: z.string().regex(/^[\w.-]+\/[\w.-]+$/),
  expectedGithubRepositoryId: z.string().regex(/^[1-9]\d*$/).nullable(),
});

interface ConnectionContext {
  databaseDisplay: string | null;
  connectionFingerprint: string;
  installationId: string;
  githubConnectedAt: string;
  repositories: z.infer<typeof repositorySchema>[];
}

/** Read-only current context. Ciphertext never leaves the server helpers. An invalid
 * connection is unknown, while failed storage reads are operational failures. */
async function currentContext(userId: string, now = Date.now()): Promise<ConnectionContext | null> {
  const identity = await loadDatabaseBindingIdentity(userId, "postgres_dsn_encrypted, postgres_connection_epoch, postgres_display", now);
  if (!identity) return null;
  const profile = profileSchema.safeParse(identity.profile);
  if (!profile.success) return null;
  return {
    databaseDisplay: profile.data.postgres_display ?? null,
    connectionFingerprint: profile.data.postgres_connection_epoch,
    installationId: profile.data.github_installation_id, githubConnectedAt: profile.data.github_connected_at,
    repositories: identity.repositories,
  };
}

function rowFor(userId: string, context: ConnectionContext, repository: ConnectionContext["repositories"][number], confirmedAt: string) {
  return { user_id: userId, repository_id: repository.id, collector: "postgres-direct" as const,
    connection_fingerprint: context.connectionFingerprint, github_installation_id: context.installationId,
    github_connected_at: context.githubConnectedAt, repository_full_name: repository.full_name, github_repo_id: repository.github_repo_id,
    confirmation_method: "customer_confirmed" as const, confirmed_at: confirmedAt };
}

/** Backend for an explicit customer decision, not automatically inferred
 * deployment evidence. No stored fact, customer database or provider is read. */
export async function getDirectRepositoryBindings(userId: string) {
  const context = await currentContext(userId);
  if (!context) return { available: false as const, repositories: [], bindings: [] };
  const { data, error } = await getSupabaseAdmin().from("database_repository_bindings").select("*")
    .eq("user_id", userId).eq("collector", "postgres-direct");
  if (error || !Array.isArray(data)) throw new Error("Binding read unavailable");
  const counts = new Map<string, number>();
  for (const row of data) if (row && typeof row.repository_id === "string") counts.set(row.repository_id, (counts.get(row.repository_id) ?? 0) + 1);
  const bindings: { repositoryId: string; method: "customer_confirmed"; confirmedAt: string }[] = [];
  for (const raw of data) {
    const row = bindingSchema.safeParse(raw);
    if (!row.success || counts.get(row.data.repository_id) !== 1) continue;
    const repository = context.repositories.find((candidate) => candidate.id === row.data.repository_id);
    if (!repository || Date.parse(row.data.confirmed_at) > Date.now() || Date.parse(row.data.confirmed_at) < Date.parse(context.githubConnectedAt)) continue;
    const expected = rowFor(userId, context, repository, row.data.confirmed_at);
    if (Object.entries(expected).some(([key, value]) => row.data[key as keyof typeof expected] !== value)) continue;
    bindings.push({ repositoryId: repository.id, method: "customer_confirmed", confirmedAt: row.data.confirmed_at });
  }
  return { available: true as const, databaseDisplay: context.databaseDisplay, connectionFingerprint: context.connectionFingerprint, installationId: context.installationId,
    githubConnectedAt: context.githubConnectedAt, repositories: context.repositories.map((repository) => ({
      id: repository.id, fullName: repository.full_name, githubRepoId: repository.github_repo_id,
    })), bindings };
}

/** Approval is tied to displayed identity. Failures never claim persistence;
 * a context recheck catches changes observed after the write, not every race. */
export async function changeDirectRepositoryBinding(userId: string, input: z.infer<typeof DirectRepositoryConfirmation>): Promise<"ok" | "stale"> {
  const context = await currentContext(userId);
  const repository = context?.repositories.find((candidate) => candidate.id === input.repositoryId);
  if (!context || !repository || input.expectedConnectionFingerprint !== context.connectionFingerprint ||
      input.expectedInstallationId !== context.installationId || input.expectedGithubConnectedAt !== context.githubConnectedAt ||
      input.expectedRepositoryFullName !== repository.full_name || input.expectedGithubRepositoryId !== repository.github_repo_id) return "stale";
  const admin = getSupabaseAdmin();
  if (input.action === "remove") {
    const { data, error } = await admin.from("database_repository_bindings").delete()
      .eq("user_id", userId).eq("collector", "postgres-direct").eq("repository_id", repository.id)
      .eq("connection_fingerprint", context.connectionFingerprint).eq("github_installation_id", context.installationId)
      .eq("github_connected_at", context.githubConnectedAt).select("repository_id");
    if (error || !Array.isArray(data) || data.some((row) => row?.repository_id !== repository.id)) throw new Error("Binding removal unavailable");
    return "ok";
  }
  const expected = rowFor(userId, context, repository, new Date(Date.now()).toISOString());
  const { data, error } = await admin.from("database_repository_bindings")
    .upsert(expected, { onConflict: "user_id,collector,repository_id" }).select("*").single();
  const receipt = bindingSchema.safeParse(data);
  if (error || !receipt.success || Object.entries(expected).some(([key, value]) => receipt.data[key as keyof typeof expected] !== value)) {
    throw new Error("Binding persistence unavailable");
  }
  const after = await currentContext(userId);
  const afterRepository = after?.repositories.find((candidate) => candidate.id === repository.id);
  if (!after || !afterRepository || after.connectionFingerprint !== context.connectionFingerprint ||
      after.installationId !== context.installationId || after.githubConnectedAt !== context.githubConnectedAt ||
      afterRepository.full_name !== repository.full_name || afterRepository.github_repo_id !== repository.github_repo_id) return "stale";
  return "ok";
}
