import { NextRequest, NextResponse } from "next/server";
import { authMcp } from "@/lib/mcpAuth";
import { GET as findings } from "@/app/api/mcp/findings/route";
import { GET as fix } from "@/app/api/mcp/fix/route";
import { GET as context } from "@/app/api/mcp/context/route";
import { GET as guardrails } from "@/app/api/mcp/guardrails/route";
import { GET as tasks } from "@/app/api/mcp/intelligence/tasks/route";
import { GET as task } from "@/app/api/mcp/intelligence/tasks/[id]/route";
import { POST as taskResult } from "@/app/api/mcp/intelligence/tasks/[id]/result/route";
import { POST as fixPr } from "@/app/api/mcp/fix/pr/route";
import { GET as fixReceipt } from "@/app/api/mcp/fix/receipts/[id]/route";
import { POST as selfCheckReport } from "@/app/api/mcp/self-check/route";
import { GET as brief } from "@/app/api/mcp/brief/route";
import { GET as posture } from "@/app/api/mcp/posture/route";
import { MCP_RESOURCES, MCP_TOOLS } from "@/lib/mcpTools";

// ShipLock's MCP server over MCP's HTTP transport (G1): a founder connects
// their own agent with one command and no npm package,
//   claude mcp add --transport http shiplock https://shiplock.dev/api/mcp/server --header "Authorization: Bearer <token>"
// Stateless JSON-RPC over POST; no server stream. The tools are exactly the
// local package's (mcp/index.mjs): reads, task polling, proposal submission,
// and a fix PR request that works only where the customer turned agent pull
// requests on (103), and the agent's report of a self-check it ran on a local
// or preview app (107). Each call runs the existing /api/mcp route in process
// with the caller's own Authorization header, so its token, two-step sign-in
// and access checks apply unchanged. No scan, file write or merge tool exists.
const PROTOCOL = "2025-06-18";
const SUPPORTED = new Set(["2025-06-18", "2025-03-26", "2024-11-05"]);
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

type Rpc = { jsonrpc?: string; id?: string | number | null; method?: unknown; params?: Record<string, unknown> };
type Handler = (req: NextRequest, ctx: { params: Promise<{ id: string }> }) => Promise<Response>;

const ok = (id: Rpc["id"], result: unknown) => NextResponse.json({ jsonrpc: "2.0", id, result });
const fail = (id: Rpc["id"], code: number, message: string, status = 200) =>
  NextResponse.json({ jsonrpc: "2.0", id: id ?? null, error: { code, message } }, { status });

/** One existing /api/mcp route, called in process with the caller's token. */
async function route(origin: string, auth: string, handler: Handler, path: string, init: { id?: string; body?: unknown } = {}) {
  const req = new NextRequest(`${origin}${path}`, {
    method: init.body === undefined ? "GET" : "POST",
    headers: { authorization: auth, "content-type": "application/json" },
    ...(init.body === undefined ? {} : { body: JSON.stringify(init.body) }),
  });
  const res = await handler(req, { params: Promise.resolve({ id: init.id ?? "" }) });
  const data = (await res.json().catch(() => ({}))) as { error?: string };
  if (!res.ok) throw new Error(data.error || `ShipLock request failed (${res.status})`);
  return data;
}

function uuid(value: unknown, message: string): string {
  if (typeof value !== "string" || !UUID.test(value)) throw new Error(message);
  return value;
}
const taskId = (value: unknown) => uuid(value, "taskId must be a task UUID");

const repoQuery = (args: Record<string, unknown>) =>
  typeof args.repository === "string" && args.repository ? `?repository=${encodeURIComponent(args.repository)}` : "";

async function callTool(origin: string, auth: string, name: unknown, args: Record<string, unknown>) {
  switch (name) {
    case "list_findings": return route(origin, auth, findings as Handler, "/api/mcp/findings");
    case "get_fix": return route(origin, auth, fix as Handler, `/api/mcp/fix?id=${encodeURIComponent(String(args.id ?? ""))}`);
    case "get_security_context": return route(origin, auth, context as Handler, `/api/mcp/context${repoQuery(args)}`);
    case "get_guardrails": return route(origin, auth, guardrails as Handler, `/api/mcp/guardrails${repoQuery(args)}`);
    case "list_intelligence_tasks": return route(origin, auth, tasks as Handler, "/api/mcp/intelligence/tasks");
    case "get_intelligence_task": { const id = taskId(args.taskId); return route(origin, auth, task as Handler, `/api/mcp/intelligence/tasks/${id}`, { id }); }
    case "submit_intelligence_result": {
      const id = taskId(args.taskId);
      return route(origin, auth, taskResult as Handler, `/api/mcp/intelligence/tasks/${id}/result`, { id, body: { result: args.result } });
    }
    case "open_fix_pull_request":
      return route(origin, auth, fixPr as Handler, "/api/mcp/fix/pr", { body: { findingId: args.findingId } });
    case "get_fix_pull_request": {
      const id = uuid(args.receiptId, "receiptId must be a UUID");
      return route(origin, auth, fixReceipt as Handler, `/api/mcp/fix/receipts/${id}`, { id });
    }
    case "report_self_check":
      return route(origin, auth, selfCheckReport as Handler, "/api/mcp/self-check",
        { body: { findingId: args.findingId, status: args.status, host: args.host, repository: args.repository } });
    default: throw new Error(`Unknown tool: ${String(name)}`);
  }
}

export async function POST(request: NextRequest) {
  let body: unknown;
  try { body = await request.json(); } catch { return fail(null, -32700, "Parse error"); }
  if (!body || typeof body !== "object" || Array.isArray(body)) return fail(null, -32600, "Send one JSON-RPC request per POST.");
  const msg = body as Rpc;
  if (msg.jsonrpc !== "2.0" || typeof msg.method !== "string") return fail(msg.id, -32600, "Invalid request.");
  // A notification needs no answer.
  if (msg.id === undefined) return new NextResponse(null, { status: 202 });

  const auth = request.headers.get("authorization") ?? "";
  if (!/^Bearer \S+$/.test(auth)) {
    return fail(msg.id, -32001, "Send your ShipLock token as a Bearer token in the Authorization header. Generate one in Settings, Your AI.", 401);
  }
  const origin = new URL(request.url).origin;
  const params = msg.params ?? {};

  switch (msg.method) {
    case "initialize": {
      // Check the token at connect, so a wrong one fails here rather than
      // reading as connected until the first call (every call checks again).
      const ctx = await authMcp(request);
      if ("error" in ctx) {
        return ctx.error.status === 401
          ? fail(msg.id, -32001, "That ShipLock token is not valid or was revoked. Generate a new one in Settings, Your AI.", 401)
          : fail(msg.id, -32001, "This ShipLock account cannot use the agent connection right now.", ctx.error.status);
      }
      const asked = typeof params.protocolVersion === "string" ? params.protocolVersion : PROTOCOL;
      return ok(msg.id, { protocolVersion: SUPPORTED.has(asked) ? asked : PROTOCOL,
        capabilities: { tools: {}, resources: {} }, serverInfo: { name: "shiplock", version: "0.3.0" } });
    }
    case "ping": return ok(msg.id, {});
    case "tools/list": return ok(msg.id, { tools: MCP_TOOLS });
    case "resources/list": return ok(msg.id, { resources: MCP_RESOURCES });
    case "tools/call": {
      try {
        const args = params.arguments && typeof params.arguments === "object" ? params.arguments as Record<string, unknown> : {};
        const result = await callTool(origin, auth, params.name, args);
        return ok(msg.id, { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] });
      } catch (err) {
        return ok(msg.id, { content: [{ type: "text", text: `Error: ${err instanceof Error ? err.message : "failed"}` }], isError: true });
      }
    }
    case "resources/read": {
      try {
        if (params.uri === "shiplock://brief") {
          const { markdown } = await route(origin, auth, brief as Handler, "/api/mcp/brief") as { markdown: string };
          return ok(msg.id, { contents: [{ uri: params.uri, mimeType: "text/markdown", text: markdown }] });
        }
        if (params.uri === "shiplock://posture") {
          const data = await route(origin, auth, posture as Handler, "/api/mcp/posture");
          return ok(msg.id, { contents: [{ uri: params.uri, mimeType: "application/json", text: JSON.stringify(data, null, 2) }] });
        }
        return fail(msg.id, -32602, `Unknown resource: ${String(params.uri)}`);
      } catch (err) {
        return fail(msg.id, -32603, err instanceof Error ? err.message : "failed");
      }
    }
    default: return fail(msg.id, -32601, `Method not found: ${msg.method}`);
  }
}

/** Stateless: no server initiated stream. */
export async function GET() {
  return new NextResponse(null, { status: 405, headers: { Allow: "POST" } });
}
