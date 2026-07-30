import { describe, expect, it } from "vitest";
import { checkUnauthenticatedMutations, checkUnvalidatedInput, scanRouteFacts } from "./routeChecks";
import { collectRoutes } from "./routeInventory";

const file = (path: string, content: string) => ({ path, content });

describe("C12 — unauthenticated mutations", () => {
  it("flags a public POST that touches data", () => {
    const routes = collectRoutes([
      file("app/api/orders/route.ts", `export async function POST(req){ const b = await req.json(); return supabase.from("orders").insert(b) }`),
    ]);
    const out = checkUnauthenticatedMutations(routes);
    expect(out).toHaveLength(1);
    expect(out[0].severity).toBe("CRITICAL");
  });

  // Most apps have public GETs; flagging them buries the one that matters.
  it("does NOT flag a public GET", () => {
    const routes = collectRoutes([
      file("app/api/posts/route.ts", `export async function GET(){ return supabase.from("posts").select() }`),
    ]);
    expect(checkUnauthenticatedMutations(routes)).toEqual([]);
  });

  it("does not flag an authenticated mutation", () => {
    const routes = collectRoutes([
      file("app/api/orders/route.ts", `export async function POST(req){ const { data:{ user } } = await supabase.auth.getUser(); return supabase.from("orders").insert({}) }`),
    ]);
    expect(checkUnauthenticatedMutations(routes)).toEqual([]);
  });

  it("does not flag a machine-gated webhook", () => {
    const routes = collectRoutes([
      file("app/api/hook/route.ts", `export async function POST(req){ const e = stripe.webhooks.constructEvent(b, s, k); return supabase.from("orders").insert({}) }`),
    ]);
    expect(checkUnauthenticatedMutations(routes)).toEqual([]);
  });

  it("does not flag a route that touches no data", () => {
    const routes = collectRoutes([file("app/api/ping/route.ts", `export async function POST(){ return new Response("ok") }`)]);
    expect(checkUnauthenticatedMutations(routes)).toEqual([]);
  });

  it("names the tables and the file so it is actionable", () => {
    const routes = collectRoutes([
      file("app/api/orders/route.ts", `export async function POST(req){ return supabase.from("orders").insert({}) }`),
    ]);
    const out = checkUnauthenticatedMutations(routes);
    expect(out[0].consequence).toContain("orders");
    expect(out[0].consequence).toContain("app/api/orders/route.ts");
  });
});

describe("C13 — mass assignment", () => {
  const routes = (content: string) => collectRoutes([file("app/api/orders/route.ts", content)]);
  const src = (content: string) => (f: string) => (f === "app/api/orders/route.ts" ? content : undefined);

  it("flags the whole body being written", () => {
    const c = `export async function POST(req){ const body = await req.json(); return supabase.from("orders").insert(body) }`;
    expect(checkUnvalidatedInput(routes(c), src(c))).toHaveLength(1);
  });

  it("flags a spread of the body", () => {
    const c = `export async function POST(req){ const body = await req.json(); return supabase.from("orders").update({ ...body }) }`;
    expect(checkUnvalidatedInput(routes(c), src(c))).toHaveLength(1);
  });

  // The calibration failures found by running this against our own codebase.
  it("does NOT flag hand-written validation", () => {
    const c = `export async function POST(req){ const body = await req.json(); let name = ""; if (typeof body.name === "string") name = body.name.trim(); return supabase.from("orders").insert({ name }) }`;
    expect(checkUnvalidatedInput(routes(c), src(c))).toEqual([]);
  });

  it("does not flag a signature-verified webhook body", () => {
    const c = `export async function POST(req){ const body = await req.text(); const event = stripe.webhooks.constructEvent(body, sig, k); return supabase.from("orders").insert({ id: event.id }) }`;
    expect(checkUnvalidatedInput(routes(c), src(c))).toEqual([]);
  });

  it("does not flag reading a single field with a default", () => {
    const c = `export async function POST(req){ const action = ((await req.json()) as { action?: string }).action ?? "enable"; return supabase.from("orders").update({ action }) }`;
    expect(checkUnvalidatedInput(routes(c), src(c))).toEqual([]);
  });

  it("does not flag an explicitly built object", () => {
    const c = `export async function POST(req){ const body = await req.json(); return supabase.from("orders").insert({ name: body.name, qty: body.qty }) }`;
    expect(checkUnvalidatedInput(routes(c), src(c))).toEqual([]);
  });

  it("is silent when a schema library is used", () => {
    const c = `import { z } from "zod";\nconst s = z.object({});\nexport async function POST(req){ const body = s.parse(await req.json()); return supabase.from("orders").insert(body) }`;
    expect(checkUnvalidatedInput(routes(c), src(c))).toEqual([]);
  });

  it("is silent when we did not read the file", () => {
    const c = `export async function POST(req){ const body = await req.json(); return supabase.from("orders").insert(body) }`;
    expect(checkUnvalidatedInput(routes(c), () => undefined)).toEqual([]);
  });

  it("names the fields an attacker would add", () => {
    const c = `export async function POST(req){ const body = await req.json(); return supabase.from("orders").insert(body) }`;
    const out = checkUnvalidatedInput(routes(c), src(c));
    expect(out[0].consequence).toContain("is_admin");
    expect(out[0].consequence).toContain("hand-written checks are fine");
  });
});

describe("scanRouteFacts", () => {
  it("returns both classes and stable ids", () => {
    const c = `export async function POST(req){ const body = await req.json(); return supabase.from("orders").insert(body) }`;
    const routes = collectRoutes([file("app/api/orders/route.ts", c)]);
    const out = scanRouteFacts(routes, () => c);
    expect(out).toHaveLength(2);
    expect(new Set(out.map((x) => x.id)).size).toBe(2);
  });

  it("is silent on a well-built route", () => {
    const c = `import { z } from "zod";\nconst s = z.object({});\nexport async function POST(req){ const { data:{user} } = await supabase.auth.getUser(); const b = s.parse(await req.json()); return supabase.from("orders").insert({}).eq("user_id", user.id) }`;
    const routes = collectRoutes([file("app/api/orders/route.ts", c)]);
    expect(scanRouteFacts(routes, () => c)).toEqual([]);
  });

  it("handles no routes", () => {
    expect(scanRouteFacts([])).toEqual([]);
  });
});
