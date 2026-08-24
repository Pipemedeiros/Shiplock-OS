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
 * Registry order is execution order, and it matters in one direction: anything
 * contributing graph facts should run before anything that reasons over them.
 * No collector here reasons — the reasoner runs in the 48h route after the whole
 * pass — but keep the invariant visible so it survives the next addition.
 */
export const DEFAULT_COLLECTORS: readonly CollectorSpec[] = [
  supabaseScanCollector,
  appSurfaceCollector,
];
