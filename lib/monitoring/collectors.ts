import { scanProject, scanCriticalChecks } from "@/lib/scanner";
import { runExposedPathScan } from "@/lib/security/exposedPathsRun";
import {
  extractFindings,
  extractCriticalFindings,
  isCriticalScopeFindingId,
  type Finding,
} from "./findings";
import type { CollectorSpec } from "./registry";

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
  eligibleTriggers: ["hourly", "deploy", "scheduled_48h"],
  // The scan makes many sequential network calls against the customer's project;
  // the full 16-check pass is the single longest thing in a monitoring run.
  timeoutMs: 45_000,
  async run(ctx) {
    if (ctx.triggerSource === "hourly") {
      const fresh = extractCriticalFindings(
        await scanCriticalChecks(ctx.profile.monitored_project_url, ctx.anonKey)
      );
      const carriedForward = ctx.previousFindings.filter((f) => !isCriticalScopeFindingId(f.id));
      return { snapshotFindings: [...carriedForward, ...fresh] };
    }

    const scan = await scanProject(ctx.profile.monitored_project_url, ctx.anonKey);
    const scanTables = (scan.tables ?? []).map((t) => ({
      name: t.name,
      rlsEnabled: t.rlsEnabled,
    }));

    return {
      snapshotFindings: extractFindings(scan),
      // Per-table RLS state for the graph's database collector. Full scans only —
      // the hourly subset does not enumerate tables, so writing from there would
      // replace a complete picture with a partial one. Merged, because the
      // Management API scan owns the other half of this namespace.
      ...(scanTables.length > 0
        ? { facts: { collector: "db" as const, facts: { scanTables }, merge: true } }
        : {}),
    };
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
  eligibleTriggers: ["deploy", "scheduled_48h"],
  timeoutMs: 30_000,
  appliesTo: (ctx) => Boolean(ctx.profile.monitored_app_url),
  async run(ctx) {
    const result = await runExposedPathScan(ctx.profile.id, ctx.profile.monitored_app_url!);
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
  eligibleTriggers: ["deploy", "scheduled_48h"],
  timeoutMs: 30_000,
  appliesTo: (ctx) => Boolean(ctx.profile.vercel_access_token_encrypted),
  async run(ctx) {
    // Self-diffing: runVercelEnvAudit owns its rows in deep_findings, so its
    // findings must not also enter the snapshot and be diffed a second time.
    const { runVercelEnvAudit } = await import("@/lib/deep/vercelRun");
    await runVercelEnvAudit(
      ctx.profile.id,
      ctx.profile.vercel_access_token_encrypted as string,
      ctx.profile.vercel_team_id ?? null,
    );
    return {};
  },
};

export const directPostgresCollector: CollectorSpec = {
  id: "postgres-direct",
  layer: "db",
  eligibleTriggers: ["deploy", "scheduled_48h"],
  // A TCP connect plus four catalogue queries, against a database that may be
  // cold-starting on a serverless plan.
  timeoutMs: 30_000,
  appliesTo: (ctx) => Boolean(ctx.profile.postgres_dsn_encrypted),
  async run(ctx) {
    // Self-diffing, like the app-surface collector: it owns rows in
    // deep_findings with their own archive-on-resolve contract, so its findings
    // must not also enter the snapshot and be diffed a second time.
    const { runDirectPostgresScan } = await import("@/lib/deep/postgresDirectRun");
    await runDirectPostgresScan(ctx.profile.id);
    return {};
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
  directPostgresCollector,
  vercelEnvCollector,
  appSurfaceCollector,
];
