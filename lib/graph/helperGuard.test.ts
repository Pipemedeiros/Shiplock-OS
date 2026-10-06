import { describe, expect, it } from "vitest";
import { analyzeRouteFile } from "./routeInventory";

// A gate one call away (ledger P1, Q38 self-scan): the route rejects with 401
// or 403 on the result of a helper it imports, and that helper's own body
// compares a secret or resolves a hashed API token. Only then is the gate the
// route's. A helper that merely mentions a secret, or whose result the route
// ignores, still credits nothing (the route stays unreadable, never anonymous
// and never gated by assumption).
const fact = (route: string, files: Record<string, string>) => {
  const byPath = new Map(Object.entries({ ...files, "app/api/x/route.ts": route }).map(([path, content]) => [path, { path, content }]));
  return analyzeRouteFile("app/api/x/route.ts", route, byPath);
};

const workerAuth = `import { timingSafeEqual } from "node:crypto";
export function isAuthorizedWorker(request: Request): boolean {
  const secret = process.env.CRON_SECRET;
  const authorization = request.headers.get("authorization");
  if (!secret || !authorization?.startsWith("Bearer ")) return false;
  const supplied = Buffer.from(authorization.slice(7)), expected = Buffer.from(secret);
  return supplied.length === expected.length && timingSafeEqual(supplied, expected);
}`;
const apiTokens = `import { createHash } from "node:crypto";
export function hashToken(raw: string) { return createHash("sha256").update(raw).digest("hex"); }
export async function resolveToken(raw: string) {
  const { data: row } = await db.from("api_tokens").select("user_id").eq("token_hash", hashToken(raw)).maybeSingle();
  if (!row) return null;
  return { userId: row.user_id as string };
}`;
const tokenAuth = `import { NextResponse } from "next/server";
import { resolveToken } from "@/lib/apiTokens";
export async function authToken(
  req: Request
): Promise<{ userId: string } | { error: NextResponse }> {
  const token = req.headers.get("authorization")?.replace("Bearer ", "").trim();
  if (!token) return { error: NextResponse.json({ error: "Authentication required." }, { status: 401 }) };
  const resolved = await resolveToken(token);
  if (!resolved) return { error: NextResponse.json({ error: "Invalid token." }, { status: 401 }) };
  return { userId: resolved.userId };
}`;
const data = `const { data } = await db.from("jobs").select("*");`;

describe("a gate one call away", () => {
  it("credits a shared-secret helper the route rejects on as the route's machine gate", () => {
    const r = fact(`import { isAuthorizedWorker } from "@/lib/workerAuth";
export async function POST(request: Request) {
  if (!isAuthorizedWorker(request)) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }
  ${data}
  return NextResponse.json(data);
}`, { "lib/workerAuth.ts": workerAuth });
    expect(r).toMatchObject({ machineGated: true, identityReadable: true, machineGateReadable: true });
    expect(r.via).toContain("lib/workerAuth.ts");
  });

  it("credits a hashed API token resolved by a helper the route rejects on as a signed-in caller", () => {
    const r = fact(`import { authToken } from "@/lib/tokenAuth";
export async function GET(req: Request) {
  const ctx = await authToken(req);
  if ("error" in ctx) return ctx.error;
  const { data } = await db.from("findings").select("*").eq("user_id", ctx.userId);
  return Response.json(data);
}`, { "lib/tokenAuth.ts": tokenAuth, "lib/apiTokens.ts": apiTokens });
    expect(r).toMatchObject({ authenticated: true, identityReadable: true, machineGated: false });
  });

  it("credits nothing when the route ignores the helper's answer", () => {
    const r = fact(`import { isAuthorizedWorker } from "@/lib/workerAuth";
export async function POST(request: Request) {
  const ok = isAuthorizedWorker(request);
  console.log("worker", ok);
  ${data}
  return Response.json(data);
}`, { "lib/workerAuth.ts": workerAuth });
    expect(r.machineGated).toBe(false);
    expect(r.identityReadable).toBe(false);
  });

  it("credits nothing when the route's failure branch does not reject", () => {
    const r = fact(`import { isAuthorizedWorker } from "@/lib/workerAuth";
export async function POST(request: Request) {
  if (!isAuthorizedWorker(request)) {
    return Response.json({ note: "running anyway" }, { status: 200 });
  }
  ${data}
  return Response.json(data);
}`, { "lib/workerAuth.ts": workerAuth });
    expect(r.machineGated).toBe(false);
  });

  it("credits nothing when the helper only reads a header and compares no secret", () => {
    const r = fact(`import { hasHeader } from "@/lib/loose";
export async function POST(request: Request) {
  if (!hasHeader(request)) return Response.json({ error: "no" }, { status: 401 });
  ${data}
  return Response.json(data);
}`, { "lib/loose.ts": `export function hasHeader(request: Request) { return Boolean(request.headers.get("authorization")); }` });
    expect(r.machineGated).toBe(false);
    expect(r.authenticated).toBe(false);
  });

  it("credits no signed-in caller for an unhashed token lookup, which proves possession, not identity", () => {
    const plain = apiTokens.replace(`.eq("token_hash", hashToken(raw))`, `.eq("invite", raw)`);
    const r = fact(`import { authToken } from "@/lib/tokenAuth";
export async function GET(req: Request) {
  const ctx = await authToken(req);
  if ("error" in ctx) return ctx.error;
  ${data}
  return Response.json(data);
}`, { "lib/tokenAuth.ts": tokenAuth, "lib/apiTokens.ts": plain });
    expect(r.authenticated).toBe(false);
  });

  it("credits nothing when the route never checks the token helper's result", () => {
    const r = fact(`import { authToken } from "@/lib/tokenAuth";
export async function GET(req: Request) {
  await authToken(req);
  ${data}
  return Response.json(data);
}`, { "lib/tokenAuth.ts": tokenAuth, "lib/apiTokens.ts": apiTokens });
    expect(r.authenticated).toBe(false);
  });

  it("credits nothing when the check runs only on some requests (corpus-t: password-protected links)", () => {
    const r = fact(`import { isAuthorizedWorker } from "@/lib/workerAuth";
export async function GET(request: Request) {
  const requiresPassword = new URL(request.url).searchParams.has("p");
  if (requiresPassword) {
    if (!isAuthorizedWorker(request)) return Response.json({ error: "x" }, { status: 401 });
  }
  ${data}
  return Response.json(data);
}`, { "lib/workerAuth.ts": workerAuth });
    expect(r.machineGated).toBe(false);
  });

  it("credits nothing when work runs before the check", () => {
    const r = fact(`import { isAuthorizedWorker } from "@/lib/workerAuth";
export async function POST(request: Request) {
  const { data } = await db.from("jobs").delete().neq("id", "");
  if (!isAuthorizedWorker(request)) return Response.json({ error: "x" }, { status: 401 });
  return Response.json(data);
}`, { "lib/workerAuth.ts": workerAuth });
    expect(r.machineGated).toBe(false);
  });

  it("credits nothing for a same-named function defined elsewhere than the import", () => {
    const r = fact(`import { isAuthorizedWorker } from "@/lib/other";
export async function POST(request: Request) {
  if (!isAuthorizedWorker(request)) return Response.json({ error: "x" }, { status: 401 });
  ${data}
  return Response.json(data);
}`, { "lib/workerAuth.ts": workerAuth, "lib/other.ts": `export function isAuthorizedWorker(request: Request) { return request.method === "POST"; }` });
    expect(r.machineGated).toBe(false);
  });

  // corpus-owner/corpus-u lib/security/route-auth.ts: the comparison sits in
  // a function declared next to the helper, not in the helper's own body.
  const routeAuth = `import { timingSafeEqual } from "node:crypto";
function bearer(request: Request) { return request.headers.get("authorization")?.slice(7) ?? ""; }
function safeEqual(a: string, b: string) { const l = Buffer.from(a), r = Buffer.from(b); return l.length === r.length && timingSafeEqual(l, r); }
export function isAutomationAuthorized(request: Request): boolean {
  const secret = process.env.INDEXER_SECRET;
  if (!secret) return false;
  return safeEqual(bearer(request), secret);
}`;
  const automationRoute = `import { isAutomationAuthorized } from "@/lib/routeAuth";
export async function GET(request: Request) {
  if (!isAutomationAuthorized(request)) return Response.json({ error: "x" }, { status: 401 });
  ${data}
  return Response.json(data);
}`;

  it("credits a comparison made by a function declared beside the helper", () => {
    expect(fact(automationRoute, { "lib/routeAuth.ts": routeAuth }).machineGated).toBe(true);
  });

  it("credits nothing when the function beside the helper compares nothing", () => {
    const loose = routeAuth.replace("return l.length === r.length && timingSafeEqual(l, r);", "return a.length > 0 && b.length > 0;");
    expect(fact(automationRoute, { "lib/routeAuth.ts": loose }).machineGated).toBe(false);
  });

  // corpus-owner/corpus-v follow-up-reminders: handlers wrapped in withError, and
  // GET and POST each reject on their own secret helper.
  const twoHelpers = workerAuth + "\n" + workerAuth.replace("isAuthorizedWorker", "isAuthorizedPost");
  const wrapped = `import { isAuthorizedWorker, isAuthorizedPost } from "@/lib/workerAuth";
export const GET = withError("x", async (request) => {
  if (!isAuthorizedWorker(request)) return new Response("Unauthorized", { status: 401 });
  ${data}
  return Response.json(data);
});
export const POST = withError("x", async (request) => {
  if (!isAuthorizedPost(request)) return new Response("Unauthorized", { status: 401 });
  ${data}
  return Response.json(data);
});`;

  it("credits handlers wrapped in a call, each rejecting on its own machine helper", () => {
    expect(fact(wrapped, { "lib/workerAuth.ts": twoHelpers }).machineGated).toBe(true);
  });

  it("credits nothing when one wrapped handler opens without a guard", () => {
    const open = wrapped.replace(`if (!isAuthorizedPost(request)) return new Response("Unauthorized", { status: 401 });`, "");
    expect(fact(open, { "lib/workerAuth.ts": twoHelpers }).machineGated).toBe(false);
  });

  it("credits nothing when the second handler's helper compares no secret", () => {
    const mixed = workerAuth + "\n" + `export function isAuthorizedPost(request: Request) { return request.method === "POST"; }`;
    expect(fact(wrapped, { "lib/workerAuth.ts": mixed }).machineGated).toBe(false);
  });

  // corpus-w lib/github-auth.ts: verifyPat checks any GitHub user's token;
  // the HMAC beside it only signs a cache entry. Not a machine gate.
  it("credits nothing for a comparison beside a helper that is handed a value, not the request", () => {
    const githubAuth = `import { createHmac, timingSafeEqual } from "crypto";
function verifyCacheValue(v: string) { const [l, sig] = v.split("."); return timingSafeEqual(Buffer.from(sig), createHmac("sha256", k).update(l).digest()) ? l : null; }
export const verifyPat = async (pat: string): Promise<string | null> => {
  const cached = await redis.get(pat);
  if (cached) return verifyCacheValue(cached);
  const res = await fetch("https://api.github.com/user", { headers: { Authorization: \`token \${pat}\` } });
  return res.ok ? (await res.json()).login : null;
};`;
    const route = `import { verifyPat } from "@/lib/githubAuth";
export async function POST(req: Request) {
  const login = await verifyPat(req.headers.get("x-gh-token") ?? "");
  if (!login) return Response.json({ error: "x" }, { status: 401 });
  ${data}
  return Response.json(data);
}`;
    expect(fact(route, { "lib/githubAuth.ts": githubAuth }).machineGated).toBe(false);
  });

  // corpus-owner/inspector /api/cron/signal-detection, corpus-v: the rejecting
  // branch logs before it returns.
  it("credits a rejecting branch that logs before it returns", () => {
    const r = fact(`import { isAuthorizedWorker } from "@/lib/workerAuth";
export async function GET(request: Request) {
  const startTime = Date.now();
  if (!isAuthorizedWorker(request)) {
    log.error("Unauthorized request");
    return Response.json({ error: "Unauthorized" }, { status: 401 });
  }
  ${data}
  return Response.json(data);
}`, { "lib/workerAuth.ts": workerAuth });
    expect(r.machineGated).toBe(true);
  });

  it("credits nothing when the failure branch does work before returning", () => {
    const r = fact(`import { isAuthorizedWorker } from "@/lib/workerAuth";
export async function GET(request: Request) {
  if (!isAuthorizedWorker(request)) {
    await db.from("jobs").delete().neq("id", "");
    return Response.json({ error: "Unauthorized" }, { status: 401 });
  }
  ${data}
  return Response.json(data);
}`, { "lib/workerAuth.ts": workerAuth });
    expect(r.machineGated).toBe(false);
  });
});
