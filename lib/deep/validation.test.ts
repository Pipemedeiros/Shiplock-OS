import { describe, expect, it } from "vitest";
import { scanSecrets, scanTokenStorage, scanLoggedSecrets, extractDependencies } from "./githubScan";
import { extractEndpoints, extractRpcs, detectMiddlewareAuthGate } from "./reasoningContext";
import type { RepoFile } from "./githubScan";

// FP/FN validation corpus. VULN plants one known issue per detector; CLEAN is the
// secure counterpart. VULN must be CAUGHT (no false negatives); CLEAN must be
// QUIET (no false positives). Kept as a permanent regression guard so the
// detectors can't silently drift out of calibration.

const VULN: RepoFile[] = [
  { path: "lib/config.ts", content: `export const k = "sb_secret_abcdef1234567890xyz";` },
  { path: ".env.production", content: `SUPABASE_SERVICE_ROLE_KEY=eyJhbGciOi...` },
  { path: "lib/log.ts", content: `export function h(req){ console.log(req.headers.authorization); }` },
  { path: "lib/supa.ts", content: `import { createClient } from "@supabase/supabase-js"; export const c = createClient(u, k);` },
  { path: "app/api/orders/route.ts", content: `export async function POST(req){ const b = await req.json(); await supabase.from("orders").update(b).eq("id", b.id); }` },
  { path: "supabase/migrations/010_promote.sql", content: `create function public.promote(uid uuid) returns void language plpgsql security definer as $$ begin update profiles set is_admin = true where id = uid; end $$;` },
  { path: "middleware.ts", content: `export async function middleware(req){ const { data:{user} } = await supabase.auth.getUser(); if(!user) return NextResponse.redirect(new URL("/login", req.url)); }` },
  { path: "package.json", content: `{"dependencies":{"lodash":"4.17.11"}}` },
];

const CLEAN: RepoFile[] = [
  { path: "lib/config.ts", content: `export const url = process.env.NEXT_PUBLIC_SUPABASE_URL;` },
  { path: "lib/log.ts", content: `export function h(){ console.log("request received"); }` },
  { path: "lib/supa.ts", content: `import { createServerClient } from "@supabase/ssr"; export const c = createServerClient(u, k, opts);` },
  { path: "app/api/me/route.ts", content: `export async function PATCH(req){ const { data:{user} } = await supabase.auth.getUser(); const { name } = await req.json(); await supabase.from("profiles").update({ name }).eq("user_id", user.id); }` },
  { path: "supabase/migrations/024_lock.sql", content: `create function public.f() returns void language sql security definer as $$ select 1 $$;
revoke execute on function public.f() from anon;` },
  { path: "middleware.ts", content: `export function middleware(){ return NextResponse.next(); }` },
  { path: "package.json", content: `{"dependencies":{"next":"16.2.9"}}` },
];

describe("VALIDATION — no false negatives on the vulnerable fixture", () => {
  it("catches the committed secret + committed .env", () => {
    const ids = scanSecrets(VULN).map((f) => f.id);
    expect(ids.some((i) => i.includes("supabase_service_key"))).toBe(true);
    expect(ids.some((i) => i.includes("committed_env"))).toBe(true);
  });
  it("catches the logged secret", () => {
    expect(scanLoggedSecrets(VULN).length).toBeGreaterThan(0);
  });
  it("catches the localStorage token storage", () => {
    expect(scanTokenStorage(VULN)).toHaveLength(1);
  });
  it("catches the mutating endpoint with no ownership scope + client input (IDOR/mass-assign)", () => {
    const orders = extractEndpoints(VULN).find((e) => e.path.includes("orders"));
    expect(orders?.mutates && !orders?.hasOwnershipScope && orders?.usesClientInputInWrite).toBe(true);
  });
  it("catches the SECURITY DEFINER RPC that's anon-callable (priv-esc)", () => {
    const promote = extractRpcs(VULN).find((r) => r.name === "promote");
    expect(promote?.securityDefiner && promote?.anonExecute).toBe(true);
  });
  it("catches the middleware-only auth gate (CVE-2025-29927 class)", () => {
    expect(detectMiddlewareAuthGate(VULN)).toBe(true);
  });
  it("extracts the vulnerable dependency for CVE lookup", () => {
    expect(extractDependencies(VULN.find((f) => f.path === "package.json")!.content, null)).toContainEqual({ name: "lodash", version: "4.17.11" });
  });
});

describe("VALIDATION — no false positives on the clean fixture", () => {
  it("no committed / logged / token-storage secrets", () => {
    expect(scanSecrets(CLEAN)).toEqual([]);
    expect(scanLoggedSecrets(CLEAN)).toEqual([]);
    expect(scanTokenStorage(CLEAN)).toEqual([]);
  });
  it("no unscoped mutating endpoint (the /me route is ownership-scoped)", () => {
    const me = extractEndpoints(CLEAN).find((e) => e.path.includes("me"));
    expect(me?.hasOwnershipScope).toBe(true);
  });
  it("the revoked SECURITY DEFINER fn is not anon-callable", () => {
    expect(extractRpcs(CLEAN).find((r) => r.name === "f")?.anonExecute).toBe(false);
  });
  it("no middleware auth gate (plain next())", () => {
    expect(detectMiddlewareAuthGate(CLEAN)).toBe(false);
  });
});
