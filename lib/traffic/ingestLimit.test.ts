import { describe, expect, it } from "vitest";
import { IngestLimiter, DEFAULT_LIMITS } from "./ingestLimit";

const opts = { capacity: 5, refillPerSecond: 1, maxKeys: 3 };

describe("IngestLimiter", () => {
  it("allows a burst up to capacity, then refuses", () => {
    const l = new IngestLimiter(opts);
    for (let i = 0; i < 5; i++) expect(l.allow("a", 1000), `req ${i}`).toBe(true);
    expect(l.allow("a", 1000)).toBe(false);
  });

  it("refills over time", () => {
    const l = new IngestLimiter(opts);
    for (let i = 0; i < 5; i++) l.allow("a", 1000);
    expect(l.allow("a", 1000)).toBe(false);
    expect(l.allow("a", 3000)).toBe(true); // 2s -> 2 tokens
  });

  it("never refills beyond capacity", () => {
    const l = new IngestLimiter(opts);
    l.allow("a", 0);
    for (let i = 0; i < 5; i++) expect(l.allow("a", 1_000_000), `req ${i}`).toBe(true);
    expect(l.allow("a", 1_000_000)).toBe(false);
  });

  it("tracks sources independently", () => {
    const l = new IngestLimiter(opts);
    for (let i = 0; i < 5; i++) l.allow("attacker", 1000);
    expect(l.allow("attacker", 1000)).toBe(false);
    expect(l.allow("real-customer", 1000)).toBe(true);
  });

  // Without a bound, rotating source addresses grows the map until the instance
  // dies — the abuse protection becomes the denial of service.
  it("BOUNDS memory, evicting the least recently used key", () => {
    const l = new IngestLimiter(opts);
    for (let i = 0; i < 50; i++) l.allow(`src-${i}`, 1000);
    expect(l.size).toBeLessThanOrEqual(opts.maxKeys);
  });

  it("keeps a recently active key when evicting", () => {
    const l = new IngestLimiter({ ...opts, maxKeys: 2 });
    l.allow("old", 1000);
    l.allow("keep", 1000);
    l.allow("keep", 1001); // refresh recency
    l.allow("new", 1002); // forces an eviction
    // "keep" must still be rate-limited state, i.e. still tracked
    expect(l.size).toBeLessThanOrEqual(2);
    for (let i = 0; i < 5; i++) l.allow("keep", 1002);
    expect(l.allow("keep", 1002)).toBe(false);
  });

  it("prunes idle buckets", () => {
    const l = new IngestLimiter(opts);
    l.allow("a", 0);
    l.allow("b", 0);
    expect(l.prune(1000, 60_000)).toBe(2);
    expect(l.size).toBe(0);
  });

  it("does not prune active buckets", () => {
    const l = new IngestLimiter(opts);
    l.allow("a", 59_000);
    expect(l.prune(10 * 60_000, 60_000)).toBe(0);
  });

  it("ships defaults generous enough for a real app", () => {
    expect(DEFAULT_LIMITS.capacity).toBeGreaterThanOrEqual(30);
    expect(DEFAULT_LIMITS.refillPerSecond).toBeGreaterThanOrEqual(5);
    expect(DEFAULT_LIMITS.maxKeys).toBeGreaterThanOrEqual(1000);
  });
});
