import { beforeEach, describe, expect, it, vi } from "vitest";

// Every cookie-authenticated mutation (including dormant handlers) refuses a cross-site request before any
// authentication, storage, GitHub, or provider work. The guard is the first
// statement, so nothing below it may run; any touched dependency throws.
const touched = vi.hoisted(() => vi.fn(() => { throw new Error("touched before the same-origin guard"); }));
vi.mock("@/lib/deep/proGate", () => ({ requireProUser: touched }));
vi.mock("@/lib/supabase", () => ({ getSupabaseAdmin: touched }));
vi.mock("@/lib/supabaseServer", () => ({ getSupabaseServer: touched }));
vi.mock("@/lib/dashboard", () => ({ requireDashboardSession: touched }));

vi.mock("@/lib/betterAuth", () => ({ getBetterAuth: touched, isBetterAuthConfigured: touched }));

const routes: [string, () => Promise<object>][] = [
  ["deep/postgres/repository", () => import("@/app/api/deep/postgres/repository/route")],
  ["deep/supabase/repository", () => import("@/app/api/deep/supabase/repository/route")],
  ["intelligence/connection", () => import("@/app/api/intelligence/connection/route")],
  ["intelligence/tasks/[id]/fix", () => import("@/app/api/intelligence/tasks/[id]/fix/route")],
  ["2fa/[...all]", () => import("@/app/api/2fa/[...all]/route")],
  ["repos", () => import("@/app/api/repos/route")],
  ["deep/supabase/scan", () => import("@/app/api/deep/supabase/scan/route")],
  ["deep/supabase/disconnect", () => import("@/app/api/deep/supabase/disconnect/route")],
  ["deep/postgres", () => import("@/app/api/deep/postgres/route")],
  ["audit", () => import("@/app/api/audit/route")],
  ["fix/pull-request", () => import("@/app/api/fix/pull-request/route")],
  ["fix/pr", () => import("@/app/api/fix/pr/route")],
  ["stack/detect", () => import("@/app/api/stack/detect/route")],
  ["traffic/sites", () => import("@/app/api/traffic/sites/route")],
  ["proving/authorize", () => import("@/app/api/proving/authorize/route")],
  ["proving/run", () => import("@/app/api/proving/run/route")],
  ["fix/rate-limit", () => import("@/app/api/fix/rate-limit/route")],
  ["fix/preview", () => import("@/app/api/fix/preview/route")],
  ["auth/welcome", () => import("@/app/api/auth/welcome/route")],
];

describe("cookie-authenticated mutations refuse cross-site requests first", () => {
  beforeEach(() => { touched.mockClear(); });
  it.each(routes)("%s", async (path, load) => {
    const handlers = await load() as Record<string, (request: Request, context: { params: Promise<{ id: string }> }) => Promise<Response>>;
    for (const method of ["POST", "PUT", "PATCH", "DELETE"].filter(m => m in handlers)) {
    for (const origin of ["https://evil.example", null]) {
      const response = await handlers[method](new Request(`https://shiplock.dev/api/${path}`, {
        method, headers: { "content-type": "application/json", ...(origin ? { origin } : {}) }, body: "{}",
      }), { params: Promise.resolve({ id: "test" }) });
      expect(response.status).toBe(403);
    }
    }
    expect(touched).not.toHaveBeenCalled();
  });
});
