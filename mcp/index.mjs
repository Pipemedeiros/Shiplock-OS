#!/usr/bin/env node
// ShipLock MCP server (stdio). Runs on the developer's machine and exposes their
// ShipLock security findings + fixes to their coding agent (Claude Code, Cursor,
// Codex). Thin read-only wrapper over /api/mcp/*, authenticated with a
// ShipLock PAT (SHIPLOCK_TOKEN). Returned fix content is for human review; this
// server cannot initiate a scan, write a file, or open a PR.
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  ListResourcesRequestSchema,
  ReadResourceRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";

const BASE = (process.env.SHIPLOCK_URL || "https://shiplock.dev").replace(/\/+$/, "");
const TOKEN = process.env.SHIPLOCK_TOKEN;

async function api(path, init = {}) {
  if (!TOKEN) throw new Error("SHIPLOCK_TOKEN is not set. Generate one in your ShipLock dashboard.");
  const res = await fetch(`${BASE}${path}`, {
    ...init,
    headers: { Authorization: `Bearer ${TOKEN}`, "content-type": "application/json", ...(init.headers || {}) },
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `ShipLock request failed (${res.status})`);
  return data;
}

const TOOLS = [
  {
    name: "list_findings",
    description:
      "List the open security findings for the connected ShipLock account (scan + deep). Returns id, title, severity, source, fix method, and a summary. Use get_fix for the full fix.",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "get_fix",
    description:
      "Get the full fix for one finding by id. Returns the fix method and, for code/DB fixes, the exact file content + target path to write into the working tree (the developer reviews the git diff and commits). DB/RLS fixes are migration files applied by the developer's own deploy — never write them to production directly. Some fixes return a deep-link URL instead.",
    inputSchema: { type: "object", properties: { id: { type: "string" } }, required: ["id"] },
  },
];

const RESOURCES = [
  { uri: "shiplock://brief", name: "ShipLock security brief", description: "Every open finding with its fix, formatted for the agent.", mimeType: "text/markdown" },
  { uri: "shiplock://posture", name: "ShipLock posture", description: "Current security posture summary (counts, last scan).", mimeType: "application/json" },
];

const server = new Server({ name: "shiplock", version: "0.1.0" }, { capabilities: { tools: {}, resources: {} } });

server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));

server.setRequestHandler(ListResourcesRequestSchema, async () => ({ resources: RESOURCES }));

server.setRequestHandler(ReadResourceRequestSchema, async (req) => {
  const { uri } = req.params;
  if (uri === "shiplock://brief") {
    const { markdown } = await api("/api/mcp/brief");
    return { contents: [{ uri, mimeType: "text/markdown", text: markdown }] };
  }
  if (uri === "shiplock://posture") {
    const posture = await api("/api/mcp/posture");
    return { contents: [{ uri, mimeType: "application/json", text: JSON.stringify(posture, null, 2) }] };
  }
  throw new Error(`Unknown resource: ${uri}`);
});

server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const { name, arguments: args = {} } = req.params;
  try {
    let result;
    if (name === "list_findings") {
      result = await api("/api/mcp/findings");
    } else if (name === "get_fix") {
      result = await api(`/api/mcp/fix?id=${encodeURIComponent(args.id)}`);
    } else {
      throw new Error(`Unknown tool: ${name}`);
    }
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  } catch (err) {
    return { content: [{ type: "text", text: `Error: ${err.message}` }], isError: true };
  }
});

await server.connect(new StdioServerTransport());
