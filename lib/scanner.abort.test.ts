import { afterEach, describe, expect, it, vi } from "vitest";
import { scanProject, scanCriticalChecks } from "./scanner";

// The endpoint scanner fans out many requests at the customer's
// project. A cancelled collector must cancel every one still in flight.
const SUPA = "https://testref.supabase.co";
const b64url = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
const ANON_JWT = `${b64url({ alg: "HS256" })}.${b64url({ role: "anon", ref: "testref" })}.sig`;

function installPendingFetch() {
  const signals: AbortSignal[] = [];
  vi.stubGlobal("fetch", vi.fn((input: unknown, init?: RequestInit) => {
    const url = String(input);
    if (url.endsWith("/rest/v1/")) return Promise.resolve(new Response(JSON.stringify({ paths: { "/orders": {} } })));
    if (url.includes("pg_tables")) return Promise.resolve(new Response(JSON.stringify([{ tablename: "orders", rowsecurity: false }])));
    const signal = init?.signal;
    if (signal) signals.push(signal);
    // Like real fetch: stays pending until its own signal fires.
    return new Promise<Response>((_resolve, reject) => {
      if (signal?.aborted) return reject(signal.reason);
      signal?.addEventListener("abort", () => reject(signal.reason), { once: true });
    });
  }));
  return signals;
}

afterEach(() => vi.unstubAllGlobals());

describe("scanner cancellation", () => {
  it("scanCriticalChecks aborts every in-flight probe when the caller aborts", async () => {
    const signals = installPendingFetch();
    const caller = new AbortController();
    const run = scanCriticalChecks(SUPA, ANON_JWT, caller.signal);
    await vi.waitFor(() => expect(signals.length).toBeGreaterThanOrEqual(5));
    expect(signals.every((s) => !s.aborted)).toBe(true);
    caller.abort(new Error("collector timed out"));
    expect(signals.every((s) => s.aborted)).toBe(true);
    await run.catch(() => {});
  });

  it("scanProject aborts every in-flight probe when the caller aborts", async () => {
    const signals = installPendingFetch();
    const caller = new AbortController();
    const run = scanProject(SUPA, ANON_JWT, undefined, caller.signal);
    await vi.waitFor(() => expect(signals.length).toBeGreaterThanOrEqual(1));
    caller.abort(new Error("collector timed out"));
    expect(signals.every((s) => s.aborted)).toBe(true);
    await run.catch(() => {});
  });
});
