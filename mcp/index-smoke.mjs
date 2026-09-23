#!/usr/bin/env node
// 10B-2a: the published MCP server against a local fake ShipLock. Proves the
// exact tool list (read tools plus task polling and proposal submission; no
// scan, file-write, merge, or PR tools) and the requests each tool sends. No
// network beyond 127.0.0.1, no model call.
import assert from "node:assert/strict";
import http from "node:http";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const TASK = "11111111-1111-4111-8111-111111111111";
const seen = [];
const server = http.createServer((req, res) => {
  let body = "";
  req.on("data", (chunk) => { body += chunk; });
  req.on("end", () => {
    seen.push({ method: req.method, url: req.url, auth: req.headers.authorization, body: body ? JSON.parse(body) : null });
    res.setHeader("content-type", "application/json");
    if (req.url === "/api/mcp/intelligence/tasks") return res.end(JSON.stringify({ tasks: [{ taskId: TASK }] }));
    if (req.url === `/api/mcp/intelligence/tasks/${TASK}`) return res.end(JSON.stringify({ identity: { taskId: TASK } }));
    if (req.url === `/api/mcp/intelligence/tasks/${TASK}/result`) return res.end(JSON.stringify({ status: "proposal_received", applied: false, prOpened: false }));
    res.statusCode = 404; res.end(JSON.stringify({ error: "not_found" }));
  });
});
await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
const { port } = server.address();

const client = new Client({ name: "shiplock-mcp-smoke", version: "1.0.0" });
const transport = new StdioClientTransport({ command: process.execPath,
  args: [fileURLToPath(new URL("./index.mjs", import.meta.url))],
  env: { PATH: process.env.PATH ?? "", SHIPLOCK_URL: `http://127.0.0.1:${port}`, SHIPLOCK_TOKEN: "slk_test_token" }, stderr: "pipe" });
try {
  await client.connect(transport, { timeout: 10_000 });
  const { tools } = await client.listTools();
  assert.deepEqual(tools.map((tool) => tool.name).sort(),
    ["get_fix", "get_intelligence_task", "list_findings", "list_intelligence_tasks", "submit_intelligence_result"]);
  for (const tool of tools) assert.doesNotMatch(tool.name, /scan|write|merge|pr|deploy/i);
  const call = (name, args = {}) => client.callTool({ name, arguments: args }, undefined, { timeout: 10_000 });
  const text = (response) => { assert.notEqual(response.isError, true); return JSON.parse(response.content[0].text); };

  assert.deepEqual(text(await call("list_intelligence_tasks")), { tasks: [{ taskId: TASK }] });
  assert.deepEqual(text(await call("get_intelligence_task", { taskId: TASK })), { identity: { taskId: TASK } });
  const receipt = text(await call("submit_intelligence_result", { taskId: TASK, result: { version: 1 } }));
  assert.equal(receipt.prOpened, false);
  const before = seen.length;
  assert.equal((await call("get_intelligence_task", { taskId: "../../admin" })).isError, true);
  assert.equal(seen.length, before, "a malformed task id must be refused before any request");

  assert.deepEqual(seen.map(({ method, url, auth }) => [method, url, auth]), [
    ["GET", "/api/mcp/intelligence/tasks", "Bearer slk_test_token"],
    ["GET", `/api/mcp/intelligence/tasks/${TASK}`, "Bearer slk_test_token"],
    ["POST", `/api/mcp/intelligence/tasks/${TASK}/result`, "Bearer slk_test_token"],
  ]);
  assert.deepEqual(seen[2].body, { result: { version: 1 } });
  console.log(JSON.stringify({ kind: "mcp-server-smoke", version: 1, tools: tools.length, requests: seen.length,
    malformedIdRefusedLocally: true, modelCalls: 0 }, null, 2));
} finally {
  await client.close();
  server.close();
}
