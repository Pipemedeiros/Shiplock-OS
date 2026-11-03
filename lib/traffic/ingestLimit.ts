// Abuse protection for our own highest-volume public endpoint.
//
// /api/traffic/ingest is unauthenticated by design — the customer's middleware
// posts to it with a site token — and it writes to traffic_events, the largest
// table we own. Before this, every request cost us a database lookup BEFORE we
// knew whether the token was even real, so a flood of garbage tokens ran up our
// Supabase bill, burned Vercel invocations, and degraded the product for real
// customers. That is an availability and cost hole in the front door of a
// security product, and we would report it as CRITICAL on a customer.
//
// This is deliberately NOT a claim to stop DDoS. Volumetric floods are absorbed
// upstream by the host's network layer; what this does is bound what a single
// abusive source can cost us at the application layer, and reject it before any
// database call.
//
// HONEST LIMITATION, stated because it changes what this is worth: serverless
// instances do not share memory, so this bounds each instance rather than the
// fleet. A distributed flood across many instances is not fully constrained by
// it. It is still worth having — it turns "unbounded cost per request" into
// "bounded per instance", it is free, and it adds no latency and no dependency.
// A global limit would need shared state (Redis/Postgres), which costs a network
// round trip on the hottest path in the product, and that trade is not obviously
// right at this stage.

interface Bucket {
  tokens: number;
  updatedAt: number;
}

interface LimiterOptions {
  /** Requests allowed in a burst. */
  capacity: number;
  /** Sustained requests per second, refilled continuously. */
  refillPerSecond: number;
  /**
   * Maximum distinct keys tracked. Load-bearing: without a bound, an attacker
   * rotating source addresses would grow this map until the instance ran out of
   * memory — turning the abuse protection into the denial of service. When full,
   * the least-recently-used key is evicted.
   */
  maxKeys: number;
}

export const DEFAULT_LIMITS: LimiterOptions = {
  // A busy real app sends a handful of events per second per visitor at most;
  // the snippet is fire-and-forget on page and API hits. 60 burst / 10 per
  // second is generous for a legitimate source and still bounds a bad one.
  capacity: 60,
  refillPerSecond: 10,
  maxKeys: 10_000,
};

export class IngestLimiter {
  private buckets = new Map<string, Bucket>();
  constructor(private readonly options: LimiterOptions = DEFAULT_LIMITS) {}

  /** Number of keys currently tracked. Exposed for tests and diagnostics. */
  get size(): number {
    return this.buckets.size;
  }

  /**
   * True when the request may proceed. Consumes one token when it returns true.
   *
   * @param key pseudonymous source identifier — never a raw IP
   * @param now injectable clock, so the refill behaviour is testable
   */
  allow(key: string, now: number = Date.now()): boolean {
    const { capacity, refillPerSecond, maxKeys } = this.options;

    let bucket = this.buckets.get(key);
    if (bucket) {
      // Re-insert to mark as most recently used; Map preserves insertion order,
      // which is what makes the eviction below actually LRU.
      this.buckets.delete(key);
    } else {
      bucket = { tokens: capacity, updatedAt: now };
    }

    const elapsedSeconds = Math.max(0, (now - bucket.updatedAt) / 1000);
    bucket.tokens = Math.min(capacity, bucket.tokens + elapsedSeconds * refillPerSecond);
    bucket.updatedAt = now;

    const permitted = bucket.tokens >= 1;
    if (permitted) bucket.tokens -= 1;

    this.buckets.set(key, bucket);

    if (this.buckets.size > maxKeys) {
      const oldest = this.buckets.keys().next();
      if (!oldest.done) this.buckets.delete(oldest.value);
    }

    return permitted;
  }

  /** Drops buckets untouched for a while, so idle memory is reclaimed. */
  prune(olderThanMs = 10 * 60_000, now: number = Date.now()): number {
    let removed = 0;
    for (const [key, bucket] of this.buckets) {
      if (now - bucket.updatedAt > olderThanMs) {
        this.buckets.delete(key);
        removed++;
      }
    }
    return removed;
  }
}

/**
 * Process-wide limiter for the ingest route.
 *
 * Module scope on purpose: it must survive between requests on the same warm
 * instance, which is the only place this can hold state at all.
 */
export const ingestLimiter = new IngestLimiter();
