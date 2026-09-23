#!/usr/bin/env node
// Scripted MCP clients, NOT Codex/Claude inference. Prints measured protocol
// evidence to stdout; does not persist artifacts or call a model/provider.
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const runs = [];
for (const host of ["codex", "claude-code"]) {
  const client = new Client({ name: "shiplock-scripted-proof", version: "1.0.0" });
  const transport = new StdioClientTransport({ command: process.execPath,
    args: [fileURLToPath(new URL("./intelligence-spike.mjs", import.meta.url)), "--synthetic", "--host", host],
    env: { PATH: process.env.PATH ?? "" }, stderr: "pipe" });
  const started = performance.now();
  try {
    await client.connect(transport, { timeout: 10_000 });
    const { tools } = await client.listTools();
    assert.deepEqual(tools.map((tool) => tool.name), ["get_task", "read_source", "submit_result", "get_result"]);
    const call = (name, args = {}) => client.callTool({ name, arguments: args }, undefined, { timeout: 10_000 });
    const value = (response) => { assert.equal(response.isError, undefined); return JSON.parse(response.content[0].text); };
    assert.deepEqual(value(await call("get_result")), { status: "pending" });
    const task = value(await call("get_task"));
    const source = value(await call("read_source", { path: task.sources[0].path }));
    assert.equal(task.permission, "propose_only");
    assert.equal(task.funding, "customer");
    const result = { version: 1, identity: task.identity, host, model: "scripted-fixture-no-model",
      status: "proposed", summary: "Disable production browser source maps.",
      citations: [{ path: source.path, sourceHash: source.sourceHash, startLine: 2, endLine: 2,
        quote: source.content.split("\n")[1] }],
      edits: [{ path: source.path, baseHash: source.sourceHash,
        content: source.content.replace("productionBrowserSourceMaps: true", "productionBrowserSourceMaps: false") }],
      usage: null };
    for (const invalid of [
      { ...result, identity: { ...result.identity, commit: "c".repeat(40) } },
      { ...result, citations: [{ ...result.citations[0], quote: "invented" }] },
      { ...result, edits: [{ ...result.edits[0], content: "export const authorize = () => true;" }] },
      { ...result, approve: true },
    ]) assert.equal((await call("submit_result", { result: invalid })).isError, true);
    assert.equal((await call("read_source", { path: "../.env" })).isError, true);
    const receipt = value(await call("submit_result", { result }));
    assert.equal(receipt.status, "proposal_received");
    assert.equal(receipt.applied, false);
    assert.equal(receipt.prOpened, false);
    assert.equal(receipt.tests, "not_run");
    assert.deepEqual(value(await call("submit_result", { result })), receipt);
    assert.equal((await call("submit_result", { result: { ...result, summary: "changed replay" } })).isError, true);
    assert.equal(value(await call("get_result")).proposal.edits[0].content, result.edits[0].content);
    assert.equal(value(await call("read_source", { path: source.path })).content, source.content);
    runs.push({ simulatedHost: host, transport: "MCP stdio", protocolPassed: true,
      rejectedCases: 6, realHostInferenceTested: false, modelCalls: 0, fileWrites: 0,
      prWrites: 0, durationMs: Math.round(performance.now() - started) });
  } finally { await client.close(); }
}
console.log(JSON.stringify({ kind: "offline-protocol-proof", version: 1, runs }, null, 2));
