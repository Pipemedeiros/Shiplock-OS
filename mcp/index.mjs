#!/usr/bin/env node
// ShipLock MCP server (stdio). Runs on the developer's machine and exposes their
// ShipLock security findings + fixes to their coding agent (Claude Code, Cursor,
// Codex). Thin wrapper over /api/mcp/*, authenticated with a ShipLock PAT
// (SHIPLOCK_TOKEN). Read tools, plus polling ShipLock intelligence tasks and
// submitting a proposal for one (AGENTS.md, approved 2026-09-23). ShipLock
// verifies every proposal against GitHub and only stores it. This server cannot
// initiate a scan, write a file, merge, or open a PR; every PR still needs the
// customer's own click in the dashboard.
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
  {
    name: "get_security_context",
    description:
      "Start here before editing a repository selected in ShipLock. Returns, as JSON: the last finished audit's time and status, auditInProgress (status and current step when one is queued or running), loop (the read, attack, map, fix, watch stages the dashboard shows, each with its state), the detected stack, the guardrails (security controls the code has today, which ShipLock's pull request check will not let a change remove), open findings with route, file and consequence, notRead (what the audit could not check), and howToUse. Built from ShipLock's stored facts: no source code, no model call. Pass repository as owner/name; it may be omitted when one repository is selected. Anything in notRead, and any route without a rule, is not known to be safe.",
    inputSchema: { type: "object", properties: { repository: { type: "string", description: "owner/name of a repository selected in ShipLock" } }, additionalProperties: false },
  },
  {
    name: "get_guardrails",
    description:
      "Read the security rules a selected repository must keep, as JSON: for each route that reaches data, which controls ShipLock observed today (signed-in caller required, rows scoped to the caller, machine secret required), the tables involved, and what to keep when editing. Read this before changing a route or its helpers; ShipLock's pull request check blocks a change that removes one of these controls. A route with no rule is not known to be safe: controls ShipLock could not read are never rules. Pass repository as owner/name; it may be omitted when the account has one selected repository. Returns guardrails null when no audit facts exist yet.",
    inputSchema: { type: "object", properties: { repository: { type: "string", description: "owner/name of a repository selected in ShipLock" } }, additionalProperties: false },
  },
  {
    name: "list_intelligence_tasks",
    description:
      "List ShipLock intelligence tasks waiting for this account's coding agent: task id, kind, repository, commit, and instruction. Kinds: review (a deep or pull request scan), attack_reasoning (reason over an audit's route inventory), attack_verification (prove or refute attack claims with quoted lines). Run on your own schedule; tasks expire, and an unanswered task stays 'AI check pending' in ShipLock.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
  },
  {
    name: "get_intelligence_task",
    description:
      "Read one intelligence task: kind, repository, commit, instruction, the file paths and SHA-256 hashes it covers, limits, and the exact JSON schema a result must match. An attack_reasoning task adds system and prompt (the audit's route inventory); an attack_verification task adds system and claims. ShipLock never sends source; read the files from your own checkout at that commit.",
    inputSchema: { type: "object", properties: { taskId: { type: "string" } }, required: ["taskId"], additionalProperties: false },
  },
  {
    name: "submit_intelligence_result",
    description:
      "Submit one result for a task, matching the task's resultSchema. Quote cited lines exactly; propose edits only for mechanical changes, and use status needs_human for anything that depends on ownership, authorization, or business policy. ShipLock checks every attack hypothesis against the audit's facts and re-reads cited files from GitHub before accepting; only a claim proved by quoted lines becomes a finding. It never applies an edit or opens a PR.",
    inputSchema: {
      type: "object",
      properties: { taskId: { type: "string" }, result: { type: "object" } },
      required: ["taskId", "result"],
      additionalProperties: false,
    },
  },
];

// Task ids are UUIDs. Refuse anything else before building a request path.
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
function taskPath(taskId) {
  if (typeof taskId !== "string" || !UUID.test(taskId)) throw new Error("taskId must be a task UUID");
  return `/api/mcp/intelligence/tasks/${taskId}`;
}

const RESOURCES = [
  { uri: "shiplock://brief", name: "ShipLock security brief", description: "Every open finding with its fix, formatted for the agent.", mimeType: "text/markdown" },
  { uri: "shiplock://posture", name: "ShipLock posture", description: "Current security posture summary (counts, last scan).", mimeType: "application/json" },
];

const server = new Server({ name: "shiplock", version: "0.2.0" }, { capabilities: { tools: {}, resources: {} } });

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
    } else if (name === "get_security_context") {
      result = await api(`/api/mcp/context${args.repository ? `?repository=${encodeURIComponent(args.repository)}` : ""}`);
    } else if (name === "get_guardrails") {
      result = await api(`/api/mcp/guardrails${args.repository ? `?repository=${encodeURIComponent(args.repository)}` : ""}`);
    } else if (name === "list_intelligence_tasks") {
      result = await api("/api/mcp/intelligence/tasks");
    } else if (name === "get_intelligence_task") {
      result = await api(taskPath(args.taskId));
    } else if (name === "submit_intelligence_result") {
      result = await api(`${taskPath(args.taskId)}/result`, { method: "POST", body: JSON.stringify({ result: args.result }) });
    } else {
      throw new Error(`Unknown tool: ${name}`);
    }
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  } catch (err) {
    return { content: [{ type: "text", text: `Error: ${err.message}` }], isError: true };
  }
});

await server.connect(new StdioServerTransport());
