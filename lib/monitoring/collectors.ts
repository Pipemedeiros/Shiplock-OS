import { scanProject, scanCriticalChecks } from "@/lib/scanner";
import { runExposedPathScan } from "@/lib/security/exposedPathsRun";
import {
  extractFindings,
  extractCriticalFindings,
  isCriticalScopeFindingId,
  type Finding,
} from "./findings";
import type { CollectorSpec } from "./registry";
import type { SupabaseEndpointSnapshot } from "@/lib/graph/graphRun";
import { currentConnectionEpoch } from "@/lib/deep/providerRepositoryMap";
import { validateSupabaseUrl } from "@/lib/sanitize";

function endpointOrigin(rawUrl: string, encryptedKey: string | null, epoch: string | null | undefined): Pick<SupabaseEndpointSnapshot,
  "endpointUrl" | "projectRef" | "identitySource" | "connectionFingerprint"> | undefined {
  const connectionFingerprint = currentConnectionEpoch(encryptedKey, epoch);
  if (!connectionFingerprint) return undefined;
  try {
    // Match the scanner's accepted target, not a raw URL containing credentials
    // or query parameters. This identifies the input endpoint, not its database.
    const endpointUrl = validateSupabaseUrl(rawUrl);
    return {
      endpointUrl, projectRef: new URL(endpointUrl).hostname.split(".")[0],
      identitySource: "validated-input", connectionFingerprint,
    };
  } catch { return undefined; }
}

/** Prior findings the pass could not re-check stay open; unread is not fixed. */
function carryUnread(previous: Finding[], fresh: Finding[], unread: string[]): Finding[] {
  const freshIds = new Set(fresh.map((f) => f.id));
  return previous.filter((f) => !freshIds.has(f.id) && unread.some((p) => f.id.startsWith(p)));
}

// The collectors themselves. Each one is the body of what used to be an inline
// branch in runMonitoringPass, moved here unchanged in behaviour so the
// orchestrator can stay a spine rather than a ladder.

/**
 * The Supabase project scan — the pass's primary source of findings.
 *
 * Depth depends on the trigger, and the carry-forward below is load-bearing:
 *
 * The hourly pass runs a 4-check subset, so its findings for everything OUTSIDE
 * that subset must be carried forward unchanged from the previous snapshot. If a
 * narrower pass silently replaced the whole snapshot, out-of-scope findings would
 * vanish and read as "resolved" (they were merely not re-checked), then reappear
 * as "new" on the next wider pass — a spurious duplicate alert for something that
 * was never fixed. The full scan needs no such handling: since check 16 was
 * promoted into it, its coverage is a strict superset of the hourly scope.
 */
export const supabaseScanCollector: CollectorSpec = {
  id: "supabase-scan",
  layer: "db",
  eligibleTriggers: ["hourly", "manual", "deploy", "scheduled_48h"],
  // The scan makes many sequential network calls against the customer's project;
  // the full 16-check pass is the single longest thing in a monitoring run.
  timeoutMs: 45_000,
  appliesTo: (ctx) => ctx.profile.monitoring_enabled !== false
    && Boolean(ctx.profile.monitored_project_url && ctx.anonKey),
  async run(ctx) {
    const encryptedKey = ctx.profile.monitored_anon_key_encrypted;
    if (!ctx.profile.monitored_project_url || !ctx.anonKey) return {};
    const unread: string[] = [];
    if (ctx.triggerSource === "hourly") {
      const fresh = extractCriticalFindings(
        await scanCriticalChecks(ctx.profile.monitored_project_url, ctx.anonKey, ctx.signal, unread)
      );
      const carriedForward = ctx.previousFindings.filter((f) => !isCriticalScopeFindingId(f.id));
      const inScopeUnread = carryUnread(ctx.previousFindings.filter((f) => isCriticalScopeFindingId(f.id)), fresh, unread);
      return { snapshotFindings: [...carriedForward, ...inScopeUnread, ...fresh] };
    }

    // Capture the supplied origin before any asynchronous collection. Later
    // profile changes must not relabel observations from the old target/key.
    const origin = endpointOrigin(ctx.profile.monitored_project_url, encryptedKey, ctx.profile.supabase_endpoint_connection_epoch);
    const scan = await scanProject(ctx.profile.monitored_project_url, ctx.anonKey, undefined, ctx.signal, unread);
    const fresh = extractFindings(scan);
    const tableReports = (scan.tables ?? []).map((t) => ({
      name: t.name,
      rlsEnabled: t.rlsEnabled,
      rlsReadable: t.rlsReadable === true,
    }));
    // Legacy flat control facts must contain observations only. A compatibility
    // fallback of `true` is coverage, never evidence that RLS is enabled.
    const scanTables = tableReports
      .filter((table) => table.rlsReadable)
      .map(({ name, rlsEnabled }) => ({ name, rlsEnabled }));
    const readableCount = tableReports.filter((table) => table.rlsReadable).length;
    const rlsReadability = readableCount === 0
      ? "unknown" as const
      : readableCount === tableReports.length
        ? "complete" as const
        : "partial" as const;
    const supabaseEndpointSnapshot: SupabaseEndpointSnapshot | undefined = origin ? {
      ...origin, collector: "supabase-scan", authzProvider: "postgres-rls",
      recordedAt: new Date().toISOString(), completeness: "unknown",
      rlsReadability, tableReports,
    } : undefined;

    return {
      snapshotFindings: [...fresh, ...carryUnread(ctx.previousFindings, fresh, unread)],
      // Replace legacy flat reports with observed values only. The
      // self-contained endpoint snapshot is replaced even for zero reports,
      // without borrowing other transports' facts or claiming that zero means
      // complete enumeration.
      // The hourly subset contributes neither because it does not enumerate.
      ...(scanTables.length > 0 || supabaseEndpointSnapshot
        ? { facts: { collector: "db" as const, facts: {
          // A valid full endpoint pass owns this legacy key, including an empty
          // readable set. Otherwise stale controls survive an unread pass.
          ...(supabaseEndpointSnapshot || scanTables.length > 0 ? { scanTables } : {}),
          ...(supabaseEndpointSnapshot ? { supabaseEndpointSnapshot } : {}),
        }, merge: true } }
        : {}),
    };
  },
};

/** Supabase Management policy/auth evidence is provider monitoring too. It was
 * previously a second direct loop in the daily request, which excluded it from
 * the monitoring job's retry and fairness domain. */
export const supabaseManagementCollector: CollectorSpec = {
  id: "supabase-management",
  layer: "db",
  eligibleTriggers: ["manual", "deploy", "scheduled_48h"],
  timeoutMs: 30_000,
  appliesTo: (ctx) => Boolean(
    ctx.profile.supabase_mgmt_token_encrypted && ctx.profile.supabase_mgmt_project_ref,
  ),
  async run(ctx) {
    const { runPolicyScan } = await import("@/lib/deep/supabaseMgmtRun");
    const result = await runPolicyScan(ctx.profile.id, { signal: ctx.signal, commit: ctx.commit });
    if (!result.ok) throw new Error(`Supabase Management collection failed: ${result.reason ?? "unknown"}`);
    return { newFindings: result.newFindings as Finding[] | undefined };
  },
};

/**
 * What the customer's app actually serves the public: exposed paths, source
 * maps, and secrets baked into the shipped JavaScript.
 *
 * Self-diffing: runExposedPathScan persists into deep_findings with its own
 * archive-on-resolve contract and returns only what is new, so these findings
 * never enter the snapshot and must not be diffed centrally.
 *
 * Full passes only. The bundle audit downloads real chunks (up to 8 per pass),
 * which is the wrong weight for something firing every hour — and unlike a
 * leaked key in the database layer, a bundle only changes when the customer
 * deploys. It runs on a schedule at all because these checks used to run exactly
 * once, at signup, which is backwards for this class of bug: a service-role key
 * rarely ships on day one, it gets introduced by a later deploy when something
 * needed to "just work". Checking only at signup checks the one moment the
 * mistake has not happened yet.
 */
export const appSurfaceCollector: CollectorSpec = {
  id: "app-surface",
  layer: "app-surface",
  eligibleTriggers: ["manual", "deploy", "scheduled_48h"],
  timeoutMs: 30_000,
  appliesTo: (ctx) => ctx.profile.monitoring_enabled !== false
    && Boolean(ctx.profile.monitored_app_url),
  async run(ctx) {
    const result = await runExposedPathScan(ctx.profile.id, ctx.profile.monitored_app_url!, { signal: ctx.signal, commit: ctx.commit });
    return { newFindings: result.newFindings as Finding[] };
  },
};

/**
 * The customer's own Postgres, read directly, for everyone who is not on
 * Supabase — Neon, Railway, Render, RDS, Fly, self-hosted.
 *
 * This fills the same "your database" slot as the Supabase connection rather
 * than adding a third one, so `appliesTo` is the only thing separating them: a
 * customer has one or the other. It contributes the same `db` graph facts, which
 * is what lets correlation fire for a stack we do not host.
 *
 * Full passes only. The hourly subset exists to be cheap and frequent against an
 * HTTP API; opening a TCP session to a customer's primary database every hour is
 * a different cost profile, and policy text does not change hourly.
 */
/**
 * The environment variable audit, on a schedule.
 *
 * This collector is the reason `collectors.registration.test.ts` exists.
 * `lib/deep/vercel.ts` and `vercelRun.ts` were written, tested and reachable
 * only from a settings button that no page rendered, which is the fifth
 * recorded instance in this repository of a collector that existed and was
 * never called. Registering it is the fix; leaving it importable is not.
 */
export const vercelEnvCollector: CollectorSpec = {
  id: "vercel-env",
  layer: "runtime",
  // Not hourly. Environment variables change when someone deploys or edits
  // them, not minute to minute, and the hourly pass is the one with a budget.
  eligibleTriggers: ["manual", "deploy", "scheduled_48h"],
  timeoutMs: 30_000,
  appliesTo: (ctx) => Boolean(currentConnectionEpoch(
    ctx.profile.vercel_access_token_encrypted, ctx.profile.vercel_connection_epoch)),
  async run(ctx) {
    // Self-diffing: runVercelEnvAudit owns its rows in deep_findings, so its
    // findings must not also enter the snapshot and be diffed a second time.
    const { runVercelEnvAudit } = await import("@/lib/deep/vercelRun");
    const result = await runVercelEnvAudit(
      ctx.profile.id,
      ctx.profile.vercel_access_token_encrypted as string,
      ctx.profile.vercel_connection_epoch as string,
      ctx.profile.vercel_team_id ?? null,
      { signal: ctx.signal, commit: ctx.commit },
    );
    return { newFindings: result.newFindings };
  },
};

export const directPostgresCollector: CollectorSpec = {
  id: "postgres-direct",
  layer: "db",
  eligibleTriggers: ["manual", "deploy", "scheduled_48h"],
  // A TCP connect plus four catalogue queries, against a database that may be
  // cold-starting on a serverless plan.
  timeoutMs: 30_000,
  appliesTo: (ctx) => Boolean(ctx.profile.postgres_dsn_encrypted),
  async run(ctx) {
    // Self-diffing, like the app-surface collector: it owns rows in
    // deep_findings with their own archive-on-resolve contract, so its findings
    // must not also enter the snapshot and be diffed a second time.
    const { runDirectPostgresScan } = await import("@/lib/deep/postgresDirectRun");
    const result = await runDirectPostgresScan(ctx.profile.id, { signal: ctx.signal, commit: ctx.commit });
    if (!result.ok) throw new Error(`Direct Postgres collection failed: ${result.reason ?? "unknown"}`);
    return { newFindings: result.newFindings as Finding[] | undefined };
  },
};

/**
 * Registry order is execution order, and it matters in one direction: anything
 * contributing graph facts should run before anything that reasons over them.
 * No collector here reasons — the reasoner runs in the 48h route after the whole
 * pass — but keep the invariant visible so it survives the next addition.
 */
export const DEFAULT_COLLECTORS: readonly CollectorSpec[] = [
  supabaseScanCollector,
  supabaseManagementCollector,
  directPostgresCollector,
  vercelEnvCollector,
  appSurfaceCollector,
];
