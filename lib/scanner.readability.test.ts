import { afterEach, describe, expect, it, vi } from "vitest";
import { scanProject, scanCriticalChecks } from "./scanner";

// 1E-2: a check that could not read its target must say so, so the monitoring
// snapshot keeps the prior finding instead of treating the outage as a fix.
const SUPA = "https://testref.supabase.co";
const b64url = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
const ANON = `${b64url({ alg: "HS256" })}.${b64url({ role: "anon", ref: "testref" })}.sig`;
const res = (body: unknown, status = 200) =>
  new Response(typeof body === "string" ? body : JSON.stringify(body), { status });

type Route = (url: string) => Response | Promise<Response>;
function install(route: Route) {
  vi.stubGlobal("fetch", vi.fn(async (input: unknown) => route(String(input))));
}
const spec = (url: string) => url.endsWith("/rest/v1/") ? res({ paths: { "/user_profiles": {}, "/orders": {} } }) : null;
const rls = (url: string) => url.includes("pg_tables")
  ? res([{ tablename: "user_profiles", rowsecurity: true }, { tablename: "orders", rowsecurity: false }]) : null;
const down = () => { throw new TypeError("fetch failed"); };

afterEach(() => vi.unstubAllGlobals());

describe("scanProject unread coverage", () => {
  it("never PATCHes production tables and reports mass assignment untested", async () => {
    install((url) => spec(url) ?? rls(url) ?? res(url.includes("pg_policies") || url.includes("/storage/") ? [] : {}));
    const unread: string[] = [];
    const result = await scanProject(SUPA, ANON, undefined, undefined, unread);
    expect(vi.mocked(fetch).mock.calls.some(([, init]) => init?.method === "PATCH")).toBe(false);
    expect(result.massAssignment).toEqual({ tested: false, results: [] });
    expect(unread).toEqual(["mass_assignment:"]);
  });

  // The PostgREST root still answers here, so root-targeted checks (rate limit,
  // bot headers, CORS) got real responses and are correctly not unread.
  it("marks every check that hit a network failure", async () => {
    install((url) => spec(url) ?? rls(url) ?? down());
    const unread: string[] = [];
    await scanProject(SUPA, ANON, undefined, undefined, unread);
    expect(new Set(unread)).toEqual(new Set([
      "rls:user_profiles", "rls:orders",
      "unauth_access:user_profiles", "unauth_access:orders",
      "mass_assignment:user_profiles", "mass_assignment:orders",
      "mass_assignment:",
      "idor:user_profiles",
      "auth_admin_endpoint", "secrets_exposure", "public_bucket:", "login_not_rate_limited",
      // No table could be probed, so the table-targeted probes did not run.
      "stack_trace_exposed", "sql_error_exposed",
    ]));
  });

  it("treats a 5xx as unread, not as a safe answer", async () => {
    install((url) => spec(url) ?? rls(url) ?? (url.includes("/auth/v1/admin/users") ? res("err", 503) : res(url.includes("pg_policies") || url.includes("/storage/") ? [] : {})));
    const unread: string[] = [];
    await scanProject(SUPA, ANON, undefined, undefined, unread);
    expect(unread).toEqual(expect.arrayContaining(["mass_assignment:", "auth_admin_endpoint"]));
  });

  it("marks every per-table family unread when RLS state cannot be read", async () => {
    install((url) => spec(url) ?? (url.includes("pg_tables") ? res("nope", 404) : res(url.includes("pg_policies") || url.includes("/storage/") ? [] : {})));
    const unread: string[] = [];
    await scanProject(SUPA, ANON, undefined, undefined, unread);
    expect(unread).toEqual(expect.arrayContaining(["rls:", "unauth_access:", "mass_assignment:"]));
  });

  it("marks per-table families unread when tables were guessed after a credential failure", async () => {
    install((url) => url.endsWith("/rest/v1/") ? res("no", 401) : rls(url) ?? res(url.includes("pg_policies") || url.includes("/storage/") ? [] : {}));
    const unread: string[] = [];
    await scanProject(SUPA, ANON, undefined, undefined, unread);
    expect(unread).toEqual(expect.arrayContaining(["rls:", "unauth_access:", "mass_assignment:", "idor:"]));
  });
});

describe("scanCriticalChecks unread coverage", () => {
  it("marks secrets and buckets unread on failure, and RLS when unreadable", async () => {
    install((url) => spec(url) ?? (url.includes("pg_tables") ? res("nope", 404) : down()));
    const unread: string[] = [];
    await scanCriticalChecks(SUPA, ANON, undefined, unread);
    expect(new Set(unread)).toEqual(new Set(["rls:", "secrets_exposure", "public_bucket:"]));
  });
});

describe("secure-auth check readability", () => {
  it("reports the login check as untested when every login probe failed", async () => {
    install((url) => spec(url) ?? rls(url) ?? (url.includes("/auth/v1/token") ? down() : res(url.includes("pg_policies") || url.includes("/storage/") ? [] : {})));
    const result = await scanProject(SUPA, ANON);
    expect(result.secureAuth).toEqual({ tested: false, loginRateLimited: false });
  });
});
