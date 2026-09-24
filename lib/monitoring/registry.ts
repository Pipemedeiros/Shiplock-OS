import type { Finding } from "./findings";
import type { MonitoredProfile, TriggerSource } from "./types";

// The collector registry.
//
// runMonitoringPass used to carry one hand-written `if` per collector, plus a
// try/catch around each. That reads fine at four collectors and becomes
// unauditable at fifteen — and worse, every new collector depended on someone
// remembering to wrap it, which is exactly the kind of thing that gets missed
// under deadline. lib/security/exposedPathsRun.ts already had the shape that
// scales (Promise.all with a per-collector .catch), so this generalises that
// pattern one level up rather than inventing a new one.
//
// The goal is narrow and worth stating so this doesn't grow into a framework:
// adding collector #16 should be a registry entry, not a new branch in the
// orchestrator, and one collector's bug must never cost the pass its other
// collectors' results.

/** Which layer of the customer's stack a collector observes. */
export type Layer = "code" | "db" | "app-surface" | "traffic" | "runtime";

/** Graph collector namespaces — constrained by migration 039's CHECK. */
export type GraphCollector = "source" | "db" | "traffic" | "runtime";

export interface CollectorContext {
  profile: MonitoredProfile;
  /** Decrypted once by the orchestrator; collectors never decrypt. */
  anonKey: string | null;
  triggerSource: TriggerSource;
  /** The previous snapshot's findings, for collectors that carry state forward. */
  previousFindings: Finding[];
  /** Registry supplies a fresh timeout signal for each run. Direct callers may
   * omit it. Transports must explicitly consume it; this is not a write fence. */
  signal?: AbortSignal;
  /** Monitor-worker only: commits a provider result under the job's lease and
   * the collected connection identity (migration 068). Absent for legacy
   * synchronous callers, which keep their own writes until 3F-C2c-5. */
  commit?: ProviderCommit;
  /** Monitor-worker only: records a provider pass that read nothing usable,
   * under the job's lease (migration 087), so Coverage can say it failed. */
  recordFailure?: ProviderFailure;
  /** Monitor-worker only: records whether the Supabase gateway log was read
   * for no-install traffic (Q8, migration 088), under the job's lease. */
  recordEdgeTraffic?: EdgeTrafficRecord;
}

/** One provider transport's collected result, committed atomically. */
export interface ProviderResult {
  transport: "postgres-direct" | "supabase-management" | "vercel" | "app-surface";
  /** Connection epoch read with the credential, or the app URL for app-surface. */
  identity: string;
  facts?: Record<string, unknown>;
  findings: (Finding & { packageName?: string | null; version?: string | null;
    vulnId?: string | null; cveId?: string | null })[];
  /** Archive active findings absent from this result (except under `unread`). */
  retire: boolean;
  unread?: string[];
  /** The append-only record of this read (5A-2, migration 087): the scope it
   * covered (project ref, host, team; never a secret) and the finding-ID
   * prefixes whose read failed. Families a transport never reads are not
   * failures and stay out of `failed`. */
  snapshot: { scope: string | null; failed: string[] };
}

/** Resolves to the findings the commit newly inserted; throws if fenced out. */
export type ProviderCommit = (result: ProviderResult) => Promise<Finding[]>;

export type ProviderFailure = (transport: ProviderResult["transport"], reason: string) => Promise<void>;

export type EdgeTrafficRecord = (projectRef: string, read: boolean) => Promise<void>;

/** A provider runner's known failure, with a short code safe to store. Any
 * other error is recorded as "failed": its message may carry provider text. */
export class ProviderReadError extends Error {
  readonly reason: string;
  constructor(reason: string) {
    const safe = /^[a-z_]{1,64}$/.test(reason) ? reason : "failed";
    super(`provider read failed: ${safe}`);
    this.name = "ProviderReadError";
    this.reason = safe;
  }
}

/**
 * What a collector hands back.
 *
 * Two distinct kinds are represented here on purpose, because the codebase
 * genuinely has both and flattening them into one shape would be a lie:
 *
 *  - `snapshotFindings` — the CURRENT state of everything this collector
 *    checks. The orchestrator diffs these centrally against the last snapshot
 *    and stores them. The Supabase scan works this way.
 *  - `newFindings` — findings a collector has already diffed and persisted
 *    itself (into deep_findings), handing back only what is new so the
 *    orchestrator can alert on it. The app-surface scan works this way, and
 *    must, because its findings live in a different table with their own
 *    archive-on-resolve contract.
 *
 * A collector may also contribute `facts` to the correlation graph. Facts and
 * findings are independent: routeInventory produces facts and no findings at
 * all, which is the point of the graph existing separately from the checks.
 */
export interface CollectorResult {
  snapshotFindings?: Finding[];
  newFindings?: Finding[];
  facts?: {
    collector: GraphCollector;
    facts: Record<string, unknown>;
    /** Merge with existing facts rather than replacing — required whenever a
     *  namespace has more than one producer (see graphRun.saveFacts). */
    merge?: boolean;
  };
}

export interface CollectorSpec {
  /** Stable id, used in logs and to identify the collector in a snapshot. */
  id: string;
  layer: Layer;
  /** The provider transport this collector reads, when it reads one; a failed
   * or timed-out pass is then recorded as that transport's snapshot. */
  transport?: ProviderResult["transport"];
  /** Triggers this collector runs on. Anything absent here simply never runs. */
  eligibleTriggers: readonly TriggerSource[];
  /**
   * Per-collector wait budget. On expiry the registry aborts its signal and
   * excludes late output. Cooperative transport cancellation and lease-fenced
   * persistence remain necessary; a timeout cannot undo a remote write.
   */
  timeoutMs: number;
  /**
   * Extra gate beyond the trigger, for collectors that need something the
   * profile may not have (an app URL, a connected installation). Returning
   * false is "not applicable", which is different from failing.
   */
  appliesTo?: (ctx: CollectorContext) => boolean;
  run: (ctx: CollectorContext) => Promise<CollectorResult>;
}

/** Outcome of one collector in one pass, for logging and for the snapshot. */
export interface CollectorOutcome {
  id: string;
  layer: Layer;
  status: "ok" | "skipped" | "failed" | "timeout";
  durationMs: number;
}

export interface RegistryRunResult {
  results: CollectorResult[];
  outcomes: CollectorOutcome[];
}

class CollectorTimeout extends Error {
  constructor(id: string, ms: number) {
    super(`collector ${id} exceeded ${ms}ms`);
    this.name = "CollectorTimeout";
  }
}

/**
 * Races a collector against its own budget.
 *
 * Settle the timeout before notifying work, so even a collector that resolves
 * synchronously from its abort listener cannot admit output after expiration.
 * Non-cooperative work can still continue; this helper is not a commit fence.
 */
function withTimeout<T>(id: string, ms: number, run: (signal: AbortSignal) => Promise<T>): Promise<T> {
  const controller = new AbortController();
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => {
      const error = new CollectorTimeout(id, ms);
      reject(error);
      controller.abort(error);
    }, ms);
    // A synchronous collector throw must follow the same timer-cleanup path.
    Promise.resolve().then(() => run(controller.signal)).then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (err) => {
        clearTimeout(timer);
        reject(err);
      }
    );
  });
}

/**
 * Run every eligible collector, isolated from one another.
 *
 * Sequential rather than parallel, deliberately. These collectors hit the same
 * customer's Supabase project and the same app host; firing them at once would
 * turn our own monitoring into a small burst against infrastructure the
 * customer is paying for, and the pass has no latency requirement that would
 * justify it. The isolation guarantee — one failure never costs the others —
 * comes from the try/catch here, not from parallelism.
 */
export async function runCollectors(
  specs: readonly CollectorSpec[],
  ctx: CollectorContext
): Promise<RegistryRunResult> {
  const results: CollectorResult[] = [];
  const outcomes: CollectorOutcome[] = [];

  for (const spec of specs) {
    if (!spec.eligibleTriggers.includes(ctx.triggerSource)) {
      outcomes.push({ id: spec.id, layer: spec.layer, status: "skipped", durationMs: 0 });
      continue;
    }
    if (spec.appliesTo && !spec.appliesTo(ctx)) {
      outcomes.push({ id: spec.id, layer: spec.layer, status: "skipped", durationMs: 0 });
      continue;
    }

    const started = Date.now();
    try {
      const result = await withTimeout(spec.id, spec.timeoutMs,
        (signal) => spec.run({ ...ctx, signal }));
      results.push(result);
      outcomes.push({
        id: spec.id,
        layer: spec.layer,
        status: "ok",
        durationMs: Date.now() - started,
      });
    } catch (err) {
      const timedOut = err instanceof CollectorTimeout;
      outcomes.push({
        id: spec.id,
        layer: spec.layer,
        status: timedOut ? "timeout" : "failed",
        durationMs: Date.now() - started,
      });
      console.error(
        `[monitor] collector ${spec.id} ${timedOut ? "timed out" : "failed"} for user ${ctx.profile.id}:`,
        err instanceof Error ? err.message : err
      );
      if (spec.transport && ctx.recordFailure) {
        const reason = timedOut ? "timeout" : err instanceof ProviderReadError ? err.reason : "failed";
        await ctx.recordFailure(spec.transport, reason).catch(() => {
          console.error(`[monitor] failure record for ${spec.id} was not stored for user ${ctx.profile.id}`);
        });
      }
    }
  }

  return { results, outcomes };
}
