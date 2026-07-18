import { describe, expect, it, vi, afterEach } from "vitest";
import { scanProject, scanCriticalChecks } from "./scanner";

// Correctness tests for the core 16-check scanner WITHOUT modifying it (frozen).
// The scanner is network-heavy, so we stub global fetch with canned Supabase/
// PostgREST responses for the endpoints the assertions depend on, and a benign
// fallback for everything else so the fanned-out checks complete. The pure
// helpers (analyzeKey, RLS mapping) are exercised through the real orchestrators.

const SUPA = "https://testref.supabase.co";

const b64url = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
const jwt = (payload: Record<string, unknown>) =>
  `${b64url({ alg: "HS256", typ: "JWT" })}.${b64url(payload)}.sig`;
const ANON_JWT = jwt({ role: "anon", ref: "testref" });
const SERVICE_JWT = jwt({ role: "service_role", ref: "testref" });

const res = (body: unknown, status = 200, headers: Record<string, string> = {}) =>
  new Response(typeof body === "string" ? body : JSON.stringify(body), { status, headers });

// profiles = RLS on, orders = RLS off (exposed).
const DEFAULT_RLS = [
  { tablename: "profiles", rowsecurity: true },
  { tablename: "orders", rowsecurity: false },
];

function installFetch(rls = DEFAULT_RLS) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: unknown) => {
      const url = String(input);
      if (url.endsWith("/rest/v1/")) return res({ paths: { "/profiles": {}, "/orders": {} } });
      if (url.includes("pg_tables")) return res(rls);
      if (url.includes("pg_policies")) return res([]);
      if (/\/rest\/v1\/(profiles|orders)\?/.test(url)) return res([{ id: 1 }]);
      return res({}); // benign default for every other check's endpoint
    })
  );
}

afterEach(() => vi.unstubAllGlobals());

describe("scanProject — key-format branch (security-critical)", () => {
  it("flags a service_role JWT as service role", async () => {
    installFetch();
    const r = await scanProject(SUPA, SERVICE_JWT);
    expect(r.keyAnalysis.isServiceRole).toBe(true);
    expect(r.exposedKeyInCode).toBe(true);
    expect(r.keyAnalysis.keyFormat).toBe("jwt");
  });
  it("flags an sb_secret_ key (service-role-equivalent) as critical", async () => {
    installFetch();
    const r = await scanProject(SUPA, "sb_secret_" + "a".repeat(24));
    expect(r.keyAnalysis.isServiceRole).toBe(true);
    expect(r.keyAnalysis.keyFormat).toBe("secret");
  });
  it("treats an anon JWT as safe (not service role)", async () => {
    installFetch();
    const r = await scanProject(SUPA, ANON_JWT);
    expect(r.keyAnalysis.isServiceRole).toBe(false);
    expect(r.keyAnalysis.role).toBe("anon");
    expect(r.exposedKeyInCode).toBe(false);
  });
  it("treats sb_publishable_ as the safe key type", async () => {
    installFetch();
    const r = await scanProject(SUPA, "sb_publishable_" + "a".repeat(24));
    expect(r.keyAnalysis.isServiceRole).toBe(false);
    expect(r.keyAnalysis.keyFormat).toBe("publishable");
  });
});

describe("scanProject — RLS mapping + appUrlChecked + unauth access", () => {
  it("maps pg_tables.rowsecurity to rlsEnabled per table", async () => {
    installFetch();
    const r = await scanProject(SUPA, ANON_JWT);
    const byName = Object.fromEntries(r.tables.map((t) => [t.name, t.rlsEnabled]));
    expect(byName.profiles).toBe(true);
    expect(byName.orders).toBe(false);
  });
  it("reports appUrlChecked based on whether an app URL was supplied", async () => {
    installFetch();
    expect((await scanProject(SUPA, ANON_JWT)).appUrlChecked).toBe(false);
    installFetch();
    expect((await scanProject(SUPA, ANON_JWT, "https://myapp.com")).appUrlChecked).toBe(true);
  });
  it("detects an RLS-off table as unauthenticated-accessible", async () => {
    installFetch();
    const r = await scanProject(SUPA, ANON_JWT);
    const orders = r.unauthAccess.results.find((x) => x.tableName === "orders");
    expect(orders?.accessible).toBe(true);
  });
});

describe("scanCriticalChecks — hourly lightweight pass", () => {
  it("flags a submitted service-role key and maps RLS presence", async () => {
    installFetch();
    const r = await scanCriticalChecks(SUPA, SERVICE_JWT);
    expect(r.keyAnalysis.isServiceRole).toBe(true);
    const byName = Object.fromEntries(r.tables.map((t) => [t.name, t.rlsEnabled]));
    expect(byName.orders).toBe(false);
    expect(byName.profiles).toBe(true);
  });
});

describe("scanProject — input validation", () => {
  it("rejects a non-Supabase URL with a clear error", async () => {
    await expect(scanProject("http://evil.example.com", ANON_JWT)).rejects.toThrow();
  });
  it("rejects a key that isn't a JWT or sb_ key", async () => {
    await expect(scanProject(SUPA, "not-a-real-key")).rejects.toThrow();
  });
});
