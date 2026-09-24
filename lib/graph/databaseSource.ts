import { z } from "zod";
import { SchemaColumns } from "@/lib/deep/schemaColumns";
import { getSupabaseAdmin } from "@/lib/supabase";
import { validateSupabaseUrl } from "@/lib/sanitize";
import { currentConnectionEpoch } from "@/lib/deep/providerRepositoryMap";
import { PgPolicyRow, SupabaseAdvisorRow } from "@/lib/deep/apiSchemas";
import type { DbFacts } from "./graphRun";

export interface DatabaseEvidence {
  /** At least one snapshot matches the profile read; not freshness or security. */
  admission: "connection-matched" | "unknown";
  /** Separate transports: neither physical database nor repository identity. */
  snapshots: Pick<DbFacts, "directPostgresSnapshot" | "supabaseManagementSnapshot" | "supabaseEndpointSnapshot">;
}

const policies = z.array(PgPolicyRow.extend({
  // The stored producer output is already normalized. Do not convert corrupt
  // stored strings/null to empty roles as the upstream transport parser can.
  roles: z.array(z.string()),
  cmd: z.enum(["SELECT", "INSERT", "UPDATE", "DELETE", "ALL"]),
}));
const tables = z.array(z.object({ name: z.string().min(1), rlsEnabled: z.boolean() }));
const endpointTables = z.array(z.object({
  name: z.string().min(1), rlsEnabled: z.boolean(), rlsReadable: z.boolean(),
}));
const base = z.object({
  authzProvider: z.literal("postgres-rls"),
  connectionFingerprint: z.string().regex(/^[a-f0-9]{64}$/),
  recordedAt: z.iso.datetime({ offset: true }),
  // All current producers explicitly write unknown. Never accept an invented
  // complete flag as permission to draw a negative conclusion.
  completeness: z.literal("unknown"),
});
const directSchema = base.extend({ collector: z.literal("postgres-direct"), policies, scanTables: tables, columns: SchemaColumns.optional() });
const managementSchema = base.extend({
  collector: z.literal("supabase-management"), projectRef: z.string().min(1).refine((value) => value === value.trim()), policies,
  columns: SchemaColumns.optional(),
  advisors: z.array(SupabaseAdvisorRow).optional(),
  // Strip loose configuration even if an older writer stored credentials.
  authConfig: z.object({ disable_signup: z.boolean().optional(), mailer_autoconfirm: z.boolean().optional() }).nullable(),
});
const endpointSchema = base.extend({
  collector: z.literal("supabase-scan"), endpointUrl: z.string(), projectRef: z.string().min(1),
  identitySource: z.literal("validated-input"),
  rlsReadability: z.enum(["unknown", "partial", "complete"]),
  tableReports: endpointTables,
}).superRefine((snapshot, context) => {
  const readable = snapshot.tableReports.filter((table) => table.rlsReadable).length;
  const actual = readable === 0 ? "unknown"
    : readable === snapshot.tableReports.length ? "complete" : "partial";
  if (snapshot.rlsReadability !== actual) {
    context.addIssue({ code: "custom", message: "RLS readability summary disagrees with reports" });
  }
});
const profileSchema = z.object({
  postgres_dsn_encrypted: z.unknown().optional(), postgres_connection_epoch: z.unknown().optional(),
  supabase_mgmt_connection_epoch: z.unknown().optional(), supabase_endpoint_connection_epoch: z.unknown().optional(),
  supabase_mgmt_token_encrypted: z.unknown().optional(), supabase_mgmt_project_ref: z.unknown().optional(),
  monitored_anon_key_encrypted: z.unknown().optional(), monitored_project_url: z.unknown().optional(),
});
const factsSchema = z.object({
  directPostgresSnapshot: z.unknown().optional(), supabaseManagementSnapshot: z.unknown().optional(),
  supabaseEndpointSnapshot: z.unknown().optional(),
});

function matches(snapshot: z.infer<typeof base>, epoch: string | null, now: number): boolean {
  return epoch !== null && Number.isFinite(now) &&
    Date.parse(snapshot.recordedAt) <= now && snapshot.connectionFingerprint === epoch;
}

/** Current-profile admission only. No decryption, provider fetch, flat fallback
 * or repository inference. Snapshots match the connection epoch read with its
 * credential (migration 067); a reconnect after this read is still a race until
 * transactional admission exists (3F-C2c). */
export async function loadCurrentDatabaseEvidence(userId: string, rawFacts: unknown, now = Date.now()): Promise<DatabaseEvidence> {
  const result: DatabaseEvidence = { admission: "unknown", snapshots: {} };
  const facts = factsSchema.safeParse(rawFacts);
  if (!facts.success) return result;
  const direct = directSchema.safeParse(facts.data.directPostgresSnapshot);
  const management = managementSchema.safeParse(facts.data.supabaseManagementSnapshot);
  const endpoint = endpointSchema.safeParse(facts.data.supabaseEndpointSnapshot);
  // Legacy-only/malformed payloads have nothing to match. Avoid an unnecessary
  // credential read and never reconstruct a snapshot from flat fields.
  if (!direct.success && !management.success && !endpoint.success) return result;
  try {
    const { data, error } = await getSupabaseAdmin().from("user_profiles")
      .select("postgres_dsn_encrypted, postgres_connection_epoch, supabase_mgmt_token_encrypted, supabase_mgmt_connection_epoch, supabase_mgmt_project_ref, monitored_anon_key_encrypted, supabase_endpoint_connection_epoch, monitored_project_url")
      .eq("id", userId).maybeSingle();
    if (error) return result;
    const profile = profileSchema.safeParse(data);
    if (!profile.success) return result;

    if (direct.success && matches(direct.data, currentConnectionEpoch(profile.data.postgres_dsn_encrypted, profile.data.postgres_connection_epoch), now)) {
      result.snapshots.directPostgresSnapshot = direct.data;
    }
    if (management.success && matches(management.data, currentConnectionEpoch(profile.data.supabase_mgmt_token_encrypted, profile.data.supabase_mgmt_connection_epoch), now) &&
        management.data.projectRef === profile.data.supabase_mgmt_project_ref) {
      result.snapshots.supabaseManagementSnapshot = management.data;
    }
    if (endpoint.success && matches(endpoint.data, currentConnectionEpoch(profile.data.monitored_anon_key_encrypted, profile.data.supabase_endpoint_connection_epoch), now)) {
      try {
        const url = validateSupabaseUrl(profile.data.monitored_project_url);
        if (endpoint.data.endpointUrl === url && endpoint.data.projectRef === new URL(url).hostname.split(".")[0]) {
          // Reports deliberately do not become scanTables/RLS control facts.
          result.snapshots.supabaseEndpointSnapshot = endpoint.data;
        }
      } catch { /* Invalid current endpoint leaves only this transport unknown. */ }
    }
    if (Object.keys(result.snapshots).length > 0) result.admission = "connection-matched";
  } catch {
    console.error("[database] Current connection evidence unavailable; admission remains unknown");
  }
  return result;
}
