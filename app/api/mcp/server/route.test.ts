import { readFileSync } from "node:fs";
import { beforeEach, describe, expect, it, vi } from "vitest";

// G1: a founder connects their agent with one command and no npm package:
//   claude mcp add --transport http shiplock https://shiplock.dev/api/mcp/server --header "Authorization: Bearer <token>"
// The endpoint is the local package's tools over MCP's HTTP transport; each
// call runs the existing /api/mcp route in process, with the caller's token,
// so every guard (token, two-step sign-in, access) applies unchanged.
const { seen, reply } = vi.hoisted(() => {
  const seen = { calls: [] as { route: string; url: string; auth: string | null; body: string | null }[] };
  const reply = (route: string, body: unknown, status = 200) => async (req: Request) => {
    seen.calls.push({ route, url: req.url, auth: req.headers.get("authorization"), body: req.method === "POST" ? await req.text() : null });
    return Response.json(body, { status });
  };
  return { seen, reply };
});
vi.mock("@/app/api/mcp/findings/route", () => ({ GET: reply("findings", { findings: [{ id: "f1" }] }) }));
vi.mock("@/app/api/mcp/fix/route", () => ({ GET: reply("fix", { id: "f1", method: "pr" }) }));
vi.mock("@/app/api/mcp/context/route", () => ({ GET: reply("context", { loop: [] }) }));
vi.mock("@/app/api/mcp/guardrails/route", () => ({ GET: reply("guardrails", { guardrails: null }) }));
vi.mock("@/app/api/mcp/intelligence/tasks/route", () => ({ GET: reply("tasks", { tasks: [] }) }));
vi.mock("@/app/api/mcp/intelligence/tasks/[id]/route", () => ({ GET: reply("task", { id: "t" }) }));
vi.mock("@/app/api/mcp/intelligence/tasks/[id]/result/route", () => ({ POST: reply("result", { outcome: "accepted" }) }));
vi.mock("@/app/api/mcp/brief/route", () => ({ GET: reply("brief", { markdown: "# Brief" }) }));
vi.mock("@/app/api/mcp/posture/route", () => ({ GET: reply("posture", { open: 0 }) }));
vi.mock("@/app/api/mcp/fix/pr/route", () => ({ POST: reply("fixPr", { receiptId: "r", status: "queued" }, 202) }));
vi.mock("@/app/api/mcp/fix/receipts/[id]/route", () => ({ GET: reply("receipt", { status: "opened" }) }));
vi.mock("@/app/api/mcp/self-check/route", () => ({ POST: reply("selfCheck", { recorded: true }) }));
vi.mock("@/app/api/mcp/scan/route", () => ({ POST: () => { throw new Error("never reachable"); } }));

import { GET, POST } from "./route";

const TASK = "11111111-2222-4333-8444-555555555555";
const rpc = (body: unknown, auth: string | null = "Bearer slp_test") => POST(new Request("https://shiplock.dev/api/mcp/server", {
  method: "POST", headers: { "content-type": "application/json", accept: "application/json, text/event-stream", ...(auth ? { authorization: auth } : {}) },
  body: JSON.stringify(body) }) as never);
const call = async (name: string, args: unknown = {}) => (await (await rpc({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name, arguments: args } })).json()).result;

beforeEach(() => { seen.calls = []; });

describe("/api/mcp/server", () => {
  it("initializes as ShipLock with tools and resources", async () => {
    const res = await rpc({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "claude-code", version: "x" } } });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ jsonrpc: "2.0", id: 1, result: { protocolVersion: "2025-06-18",
      capabilities: { tools: {}, resources: {} }, serverInfo: { name: "shiplock", version: "0.3.0" } } });
  });

  it("accepts a notification with no body", async () => {
    const res = await rpc({ jsonrpc: "2.0", method: "notifications/initialized" });
    expect(res.status).toBe(202);
  });

  // 103 (Felipe 2026-10-15): one PR request tool, refused by the route unless
  // the customer turned agent pull requests on; still no scan, write or merge.
  it("lists exactly the local package's tools: reads, task polling, proposals and the fix PR request, never scan, write or merge", async () => {
    const local = [...readFileSync("mcp/index.mjs", "utf8").matchAll(/name: "([a-z_]+)",\n\s+description/g)].map((m) => m[1]);
    const { tools } = (await (await rpc({ jsonrpc: "2.0", id: 3, method: "tools/list" })).json()).result;
    const names = tools.map((t: { name: string }) => t.name);
    expect(names).toEqual(local);
    expect(local).toHaveLength(10);
    expect(names.filter((n: string) => /pull|pr\b/.test(n))).toEqual(["open_fix_pull_request", "get_fix_pull_request"]);
    expect(names.join(" ")).not.toMatch(/scan|merge|write/);
  });

  it("sends a self-check report with only the finding, status, host and repository", async () => {
    await call("report_self_check", { findingId: "agent:x", status: 404, host: "localhost:3000", method: "DELETE", path: "/admin" });
    expect(seen.calls.map((c) => [c.route, c.url, c.body])).toEqual([
      ["selfCheck", "https://shiplock.dev/api/mcp/self-check", JSON.stringify({ findingId: "agent:x", status: 404, host: "localhost:3000" })],
    ]);
  });

  it("sends the PR request to the guarded route with only the finding id", async () => {
    await call("open_fix_pull_request", { findingId: "agent:x", content: "ignored" });
    await call("get_fix_pull_request", { receiptId: TASK });
    expect(seen.calls.map((c) => [c.route, c.url, c.body])).toEqual([
      ["fixPr", "https://shiplock.dev/api/mcp/fix/pr", JSON.stringify({ findingId: "agent:x" })],
      ["receipt", `https://shiplock.dev/api/mcp/fix/receipts/${TASK}`, null],
    ]);
    expect(await call("get_fix_pull_request", { receiptId: "../x" })).toMatchObject({ isError: true });
  });

  it("runs a tool through the existing route with the caller's token", async () => {
    expect(await call("list_findings")).toEqual({ content: [{ type: "text", text: JSON.stringify({ findings: [{ id: "f1" }] }, null, 2) }] });
    expect(seen.calls).toEqual([{ route: "findings", url: "https://shiplock.dev/api/mcp/findings", auth: "Bearer slp_test", body: null }]);
  });

  it("passes arguments as the routes expect them", async () => {
    await call("get_fix", { id: "a b" });
    await call("get_security_context", { repository: "acme/app" });
    await call("submit_intelligence_result", { taskId: TASK, result: { status: "proposed" } });
    expect(seen.calls.map((c) => [c.route, c.url, c.body])).toEqual([
      ["fix", "https://shiplock.dev/api/mcp/fix?id=a%20b", null],
      ["context", "https://shiplock.dev/api/mcp/context?repository=acme%2Fapp", null],
      ["result", `https://shiplock.dev/api/mcp/intelligence/tasks/${TASK}/result`, JSON.stringify({ result: { status: "proposed" } })],
    ]);
  });

  it("refuses a task id that is not a UUID before building a path", async () => {
    expect(await call("get_intelligence_task", { taskId: "../../admin" })).toEqual({ content: [{ type: "text", text: "Error: taskId must be a task UUID" }], isError: true });
    expect(seen.calls).toEqual([]);
  });

  it("answers an unknown tool as a tool error", async () => {
    expect(await call("no_such_tool")).toEqual({ content: [{ type: "text", text: "Error: Unknown tool: no_such_tool" }], isError: true });
  });

  it("reads the brief and posture resources", async () => {
    const brief = (await (await rpc({ jsonrpc: "2.0", id: 5, method: "resources/read", params: { uri: "shiplock://brief" } })).json()).result;
    expect(brief).toEqual({ contents: [{ uri: "shiplock://brief", mimeType: "text/markdown", text: "# Brief" }] });
  });

  it("requires a token, and answers unknown methods and malformed requests as JSON-RPC errors", async () => {
    const anonymous = await rpc({ jsonrpc: "2.0", id: 6, method: "tools/list" }, null);
    expect(anonymous.status).toBe(401);
    expect((await anonymous.json()).error.code).toBe(-32001);
    expect((await (await rpc({ jsonrpc: "2.0", id: 7, method: "sampling/createMessage" })).json()).error.code).toBe(-32601);
    expect((await (await rpc([{ jsonrpc: "2.0", id: 8, method: "tools/list" }])).json()).error.code).toBe(-32600);
    expect(seen.calls).toEqual([]);
  });

  it("opens no server stream", async () => {
    expect((await GET()).status).toBe(405);
  });
});
