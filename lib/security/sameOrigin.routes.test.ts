import { beforeEach, describe, expect, it, vi } from "vitest";

// Every cookie-authenticated mutation (16 routes) refuses a cross-site request before any
// authentication, storage, GitHub, or provider work. The guard is the first
// statement, so nothing below it may run; any touched dependency throws.
const touched = vi.hoisted(() => vi.fn(() => { throw new Error("touched before the same-origin guard"); }));
vi.mock("@/lib/deep/proGate", () => ({ requireProUser: touched }));
vi.mock("@/lib/supabase", () => ({ getSupabaseAdmin: touched }));
vi.mock("@/lib/supabaseServer", () => ({ getSupabaseServer: touched }));
vi.mock("@/lib/dashboard", () => ({ requireDashboardSession: touched }));

const routes: [string, () => Promise<{ POST: (request: Request) => Promise<Response> }>][] = [
  ["repos", () => import("@/app/api/repos/route")],
  ["deep/vercel/scan", () => import("@/app/api/deep/vercel/scan/route")],
  ["deep/vercel/disconnect", () => import("@/app/api/deep/vercel/disconnect/route")],
  ["deep/supabase/scan", () => import("@/app/api/deep/supabase/scan/route")],
  ["deep/supabase/disconnect", () => import("@/app/api/deep/supabase/disconnect/route")],
  ["deep/postgres", () => import("@/app/api/deep/postgres/route")],
  ["deep/github/scan", () => import("@/app/api/deep/github/scan/route")],
  ["deep/github/disconnect", () => import("@/app/api/deep/github/disconnect/route")],
  ["audit", () => import("@/app/api/audit/route")],
  ["fix/pull-request", () => import("@/app/api/fix/pull-request/route")],
  ["fix/pr", () => import("@/app/api/fix/pr/route")],
  ["stack/detect", () => import("@/app/api/stack/detect/route")],
  ["traffic/sites", () => import("@/app/api/traffic/sites/route")],
  ["proving/authorize", () => import("@/app/api/proving/authorize/route")],
  ["proving/run", () => import("@/app/api/proving/run/route")],
  ["fix/rate-limit", () => import("@/app/api/fix/rate-limit/route")],
  ["fix/preview", () => import("@/app/api/fix/preview/route")],
];

describe("cookie-authenticated mutations refuse cross-site requests first", () => {
  beforeEach(() => { touched.mockClear(); });
  it.each(routes)("%s", async (path, load) => {
    const { POST } = await load();
    for (const origin of ["https://evil.example", null]) {
      const response = await POST(new Request(`https://shiplock.dev/api/${path}`, {
        method: "POST", headers: { "content-type": "application/json", ...(origin ? { origin } : {}) }, body: "{}",
      }));
      expect(response.status).toBe(403);
    }
    expect(touched).not.toHaveBeenCalled();
  });
});
