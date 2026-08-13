// Wall-clock budgeting for the cron passes.
//
// Every monitoring route runs inside a serverless function with a hard 60s
// ceiling (maxDuration). When the customer count times the per-customer cost
// exceeds that, the platform kills the function mid-loop: the remaining users
// are simply not processed, nothing is recorded about it, and the next run
// starts from the same place and drops the same tail. The failure is silent by
// construction, which is what makes it dangerous — a customer's dashboard keeps
// saying monitoring is on.
//
// Two things fix the fairness half of that (the throughput half needs a real job
// queue, which is a separate piece of work):
//
//  1. Order by staleness, so whoever waited longest goes first and the backlog
//     rotates rather than the same head-of-list users winning every run.
//  2. Stop deliberately before the ceiling instead of being killed at it, so the
//     work that DID happen is recorded and reported rather than lost mid-write.
//
// A fixed LIMIT was the obvious alternative and is worse: it has to be tuned to
// the slowest plausible customer or it still overruns, which means on a fast run
// it leaves most of the budget unused. A time budget adapts to what the pass
// actually costs today.

/** How much of the function's ceiling to leave for the work after the loop. */
const DEFAULT_RESERVE_MS = 8_000;

export interface PassBudget {
  /** True while there is enough time left to attempt another user. */
  hasTimeFor: (estimatedMs: number) => boolean;
  /** Milliseconds elapsed since the budget started. */
  elapsedMs: () => number;
  /** Users skipped because the budget ran out, for the response payload. */
  recordSkipped: (n: number) => void;
  skippedCount: () => number;
}

/**
 * @param ceilingMs  the function's maxDuration, in milliseconds
 * @param reserveMs  time to leave for post-loop work (snapshots, digests,
 *                   the response itself). Being killed while writing is worse
 *                   than stopping early with a clean report.
 */
export function startPassBudget(
  ceilingMs: number,
  reserveMs: number = DEFAULT_RESERVE_MS
): PassBudget {
  const started = Date.now();
  let skipped = 0;
  const usable = Math.max(0, ceilingMs - reserveMs);

  return {
    hasTimeFor: (estimatedMs: number) => Date.now() - started + estimatedMs <= usable,
    elapsedMs: () => Date.now() - started,
    recordSkipped: (n: number) => {
      skipped += n;
    },
    skippedCount: () => skipped,
  };
}

/**
 * A running estimate of what one user costs this pass.
 *
 * Seeded optimistically and updated from real measurements, so the budget
 * adapts within a single run: if the first few users are slow, the pass stops
 * admitting new ones sooner rather than being killed partway through the tenth.
 * Uses the observed MAXIMUM rather than the mean deliberately — the cost of
 * underestimating is being killed mid-write, and the cost of overestimating is
 * deferring one user to the next run, which the staleness ordering will pick up
 * first anyway.
 */
export function createCostEstimator(seedMs: number) {
  let worst = seedMs;
  return {
    estimate: () => worst,
    record: (ms: number) => {
      if (ms > worst) worst = ms;
    },
  };
}
