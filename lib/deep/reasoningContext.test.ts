import { describe, expect, it } from "vitest";
import { extractEndpoints, extractRpcs, isRouteFile } from "./reasoningContext";
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

describe("extractRpcs", () => {
  it("flags a SECURITY DEFINER function granted to anon", () => {
    const files: RepoFile[] = [
      {
        path: "supabase/migrations/010_fn.sql",
        content: `create function public.use_promo_code(code text) returns void language plpgsql security definer as $$ begin end $$;
grant execute on function public.use_promo_code(text) to anon;`,
      },
    ];
    const rpcs = extractRpcs(files);
    const fn = rpcs.find((r) => r.name === "use_promo_code");
    expect(fn?.securityDefiner).toBe(true);
    expect(fn?.anonExecute).toBe(true);
  });

  it("does not flag a plain function with no grant", () => {
    const rpcs = extractRpcs([
      { path: "m.sql", content: "create function public.helper() returns int language sql as $$ select 1 $$;" },
    ]);
    expect(rpcs.find((r) => r.name === "helper")?.anonExecute).toBe(false);
  });
});
