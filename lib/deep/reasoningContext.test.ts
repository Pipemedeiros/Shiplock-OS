import { describe, expect, it } from "vitest";
import { extractEndpoints, extractRpcs, isRouteFile, detectMiddlewareAuthGate } from "./reasoningContext";
import type { RepoFile } from "./githubScan";

describe("isRouteFile", () => {
  it("matches Next route handlers + pages api", () => {
    expect(isRouteFile("app/api/orders/route.ts")).toBe(true);
    expect(isRouteFile("pages/api/orders.ts")).toBe(true);
    expect(isRouteFile("app/dashboard/page.tsx")).toBe(false);
    expect(isRouteFile("lib/util.ts")).toBe(false);
  });
});

describe("extractEndpoints", () => {
  it("flags a mutating endpoint with no ownership scope", () => {
    const files: RepoFile[] = [
      {
        path: "app/api/orders/route.ts",
        content: `export async function POST(req) { const b = await req.json(); await supabase.from("orders").update(b).eq("id", b.id); }`,
      },
    ];
    const [e] = extractEndpoints(files);
    expect(e.mutates).toBe(true);
    expect(e.hasOwnershipScope).toBe(false);
    expect(e.usesClientInputInWrite).toBe(true);
    expect(e.methods).toContain("POST");
  });

  it("recognizes an ownership-scoped, authed endpoint", () => {
    const files: RepoFile[] = [
      {
        path: "app/api/me/route.ts",
        content: `export async function PATCH(req){ const { data:{user} } = await supabase.auth.getUser(); await supabase.from("profiles").update({name}).eq("user_id", user.id); }`,
      },
    ];
    const [e] = extractEndpoints(files);
    expect(e.hasAuth).toBe(true);
    expect(e.hasOwnershipScope).toBe(true);
  });

  it("ignores non-route files", () => {
    expect(extractEndpoints([{ path: "lib/x.ts", content: "export function POST(){}" }])).toEqual([]);
  });
});

describe("detectMiddlewareAuthGate", () => {
  it("detects a session-based middleware that redirects (CVE-2025-29927 class)", () => {
    const files: RepoFile[] = [
      { path: "middleware.ts", content: `export async function middleware(req){ const {data:{user}} = await supabase.auth.getUser(); if(!user) return NextResponse.redirect(new URL("/auth", req.url)); }` },
    ];
    expect(detectMiddlewareAuthGate(files)).toBe(true);
  });

  it("ignores a middleware that only refreshes/sets headers (no access decision)", () => {
    const files: RepoFile[] = [
      { path: "middleware.ts", content: `export function middleware(){ const res = NextResponse.next(); res.headers.set("x-nonce", n); return res; }` },
    ];
    expect(detectMiddlewareAuthGate(files)).toBe(false);
  });

  it("is false when there is no middleware", () => {
    expect(detectMiddlewareAuthGate([{ path: "app/api/x/route.ts", content: "export function GET(){}" }])).toBe(false);
  });
});

describe("extractRpcs", () => {
  // Postgres default-grants EXECUTE to PUBLIC, so a SECURITY DEFINER function is
  // anon-callable UNLESS explicitly revoked — the real vuln class.
  it("treats a SECURITY DEFINER function as anon-callable by default (no grant needed)", () => {
    const rpcs = extractRpcs([
      { path: "m.sql", content: `create function public.use_promo_code(code text) returns void language plpgsql security definer as $$ begin end $$;` },
    ]);
    const fn = rpcs.find((r) => r.name === "use_promo_code");
    expect(fn?.securityDefiner).toBe(true);
    expect(fn?.anonExecute).toBe(true); // default grant → callable
  });

  it("marks anonExecute false once explicitly REVOKEd from anon", () => {
    const rpcs = extractRpcs([
      {
        path: "m.sql",
        content: `create function public.f() returns void language sql security definer as $$ select 1 $$;
revoke execute on function public.f() from anon;`,
      },
    ]);
    expect(rpcs.find((r) => r.name === "f")?.anonExecute).toBe(false);
  });

  it("excludes trigger functions (not RPC-callable)", () => {
    const rpcs = extractRpcs([
      { path: "m.sql", content: `create function public.handle_new_user() returns trigger language plpgsql security definer as $$ begin return new; end $$;` },
    ]);
    expect(rpcs.find((r) => r.name === "handle_new_user")?.anonExecute).toBe(false);
  });
});
