import { describe, expect, it } from "vitest";
import { scanSecrets, extractDependencies } from "./githubScan";
import type { RepoFile } from "./githubScan";

// FP/FN validation corpus. VULN plants one known issue per detector; CLEAN is the
// secure counterpart. VULN must be CAUGHT (no false negatives); CLEAN must be
// QUIET (no false positives). Kept as a permanent regression guard so the
// detectors can't silently drift out of calibration.

const VULN: RepoFile[] = [
  { path: "lib/config.ts", content: `export const k = "sb_secret_abcdef1234567890xyz";` },
  { path: ".env.production", content: `SUPABASE_SERVICE_ROLE_KEY=eyJhbGciOi...` },
  { path: "app/api/orders/route.ts", content: `export async function POST(req){ const b = await req.json(); await supabase.from("orders").update(b).eq("id", b.id); }` },
  { path: "supabase/migrations/010_promote.sql", content: `create function public.promote(uid uuid) returns void language plpgsql security definer as $$ begin update profiles set is_admin = true where id = uid; end $$;` },
  { path: "middleware.ts", content: `export async function middleware(req){ const { data:{user} } = await supabase.auth.getUser(); if(!user) return NextResponse.redirect(new URL("/login", req.url)); }` },
  { path: "package.json", content: `{"dependencies":{"lodash":"4.17.11"}}` },
];

const CLEAN: RepoFile[] = [
  { path: "lib/config.ts", content: `export const url = process.env.NEXT_PUBLIC_SUPABASE_URL;` },
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
  it("extracts the vulnerable dependency for CVE lookup", () => {
    expect(extractDependencies(VULN.find((f) => f.path === "package.json")!.content, null)).toContainEqual({ name: "lodash", version: "4.17.11" });
  });
});

describe("VALIDATION — no false positives on the clean fixture", () => {
  it("no committed secrets", () => {
    expect(scanSecrets(CLEAN)).toEqual([]);
  });
});
