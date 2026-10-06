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
});
