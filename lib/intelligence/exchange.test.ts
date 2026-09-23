import { describe, expect, it } from "vitest";
import { createIntelligenceExchange, sourceHash } from "./exchange";
import { disableProductionSourceMaps } from "@/lib/fixes/codemods";
import { judgeEdit } from "@/lib/agent/editGuard";

const identity = {
  taskId: "11111111-1111-4111-8111-111111111111",
  tenantId: "22222222-2222-4222-8222-222222222222",
  repositoryId: "33333333-3333-4333-8333-333333333333",
  commit: "a".repeat(40), connectionEpoch: "b".repeat(64), attempt: 1,
};
const path = "next.config.ts";
const before = "const config = {\n  productionBrowserSourceMaps: true,\n};\nexport default config;\n";
const after = disableProductionSourceMaps({ path, content: before }, {} as never)!.content;
const result = () => ({
  version: 1, identity: { ...identity }, host: "codex", model: "customer-model",
  status: "proposed", summary: "Disable public production browser source maps.",
  citations: [{ path, sourceHash: sourceHash(before), startLine: 2, endLine: 2,
    quote: "  productionBrowserSourceMaps: true," }],
  edits: [{ path, baseHash: sourceHash(before), content: after }],
  usage: null,
});
function setup(host: "codex" | "claude-code" = "codex") {
  let time = 1_000;
  let current = { ...identity };
  const exchange = createIntelligenceExchange({
    identity, host, files: [{ path, content: before }],
    instruction: "Propose the existing source-map codemod; do not apply it.",
    expiresAt: 2_000, now: () => time, currentIdentity: () => current,
    validateEdit: (file, proposed) => proposed === after &&
      judgeEdit(file.path, file.content, proposed).safe,
  });
  return { exchange, expire: () => { time = 2_000; },
    rotate: () => { current = { ...identity, connectionEpoch: "c".repeat(64) }; },
    deselect: () => { current = null as never; } };
}

describe("customer intelligence exchange (offline contract, no inference)", () => {
  it.each(["codex", "claude-code"] as const)("accepts a scoped %s proposal with source evidence", (host) => {
    const { exchange } = setup(host);
    expect(exchange.getTask()).toMatchObject({ identity, host, funding: "customer",
      permission: "propose_only", status: "pending" });
    expect(exchange.readSource(path)).toMatchObject({ content: before, sourceHash: sourceHash(before) });
    const receipt = exchange.submit({ ...result(), host });
    expect(receipt).toMatchObject({ status: "proposal_received", tests: "not_run",
      applied: false, prOpened: false, modelUsageVerified: false });
    expect(exchange.getResult()).toMatchObject({ receipt, proposal: { edits: [{ content: after }] } });
    expect(exchange.getTask().status).toBe("proposal_received");
  });

  it("keeps an offline host pending until an explicit unavailable response", () => {
    const { exchange } = setup();
    expect(exchange.getResult()).toEqual({ status: "pending" });
    const receipt = exchange.submit({ ...result(), status: "unavailable",
      reason: "host_offline", citations: [], edits: [] });
    expect(receipt.status).toBe("unavailable");
    expect(exchange.getResult()).toMatchObject({ receipt, proposal: null,
      outcome: { status: "unavailable", reason: "host_offline" } });
  });

  it("allows human-review outcomes without treating them as fixes", () => {
    const { exchange } = setup();
    expect(exchange.submit({ ...result(), status: "needs_human", edits: [] }).status).toBe("needs_human");
    expect(exchange.getResult()).toMatchObject({ outcome: { status: "needs_human",
      summary: result().summary }, proposal: null });
  });

  it.each(["taskId", "tenantId", "repositoryId", "commit", "connectionEpoch", "attempt"])(
    "rejects a different %s", (key) => {
      const input = result();
      Object.assign(input.identity, { [key]: key === "attempt" ? 2 : key === "commit" ? "d".repeat(40)
        : key === "connectionEpoch" ? "d".repeat(64) : "44444444-4444-4444-8444-444444444444" });
      expect(() => setup().exchange.submit(input)).toThrow("scope_mismatch");
    });

  it.each(["expire", "rotate", "deselect"] as const)("rejects results and source reads after %s", (change) => {
    const run = setup();
    run[change]();
    expect(() => run.exchange.submit(result())).toThrow(/expired|scope_changed/);
    expect(() => run.exchange.readSource(path)).toThrow(/expired|scope_changed/);
  });

  it("returns the same receipt for an exact retry but refuses changed replays", () => {
    const { exchange } = setup();
    const receipt = exchange.submit(result());
    expect(exchange.submit(result())).toEqual(receipt);
    expect(() => exchange.submit({ ...result(), summary: "different" })).toThrow("already_completed");
  });

  it.each(["../.env", "/etc/passwd", ".env", "app/api/private.ts", "next.config.ts/../.env"])(
    "refuses unlisted source %s", (file) => expect(() => setup().exchange.readSource(file)).toThrow("source_not_allowed"));

  it.each([
    ["forged quote", (r: ReturnType<typeof result>) => { r.citations[0].quote = "invented evidence"; }],
    ["wrong lines", (r: ReturnType<typeof result>) => { r.citations[0].endLine = 100; }],
    ["old source", (r: ReturnType<typeof result>) => { r.citations[0].sourceHash = "f".repeat(64); }],
    ["old base", (r: ReturnType<typeof result>) => { r.edits[0].baseHash = "f".repeat(64); }],
    ["unlisted edit", (r: ReturnType<typeof result>) => { r.edits[0].path = "auth.ts"; }],
    ["uncited edit", (r: ReturnType<typeof result>) => { r.citations = []; }],
    ["business-policy edit", (r: ReturnType<typeof result>) => { r.edits[0].content = "export const isAdmin = () => true;"; }],
    ["duplicate edit", (r: ReturnType<typeof result>) => { r.edits.push(r.edits[0]); }],
    ["host spoof", (r: ReturnType<typeof result>) => { r.host = "claude-code"; }],
  ] as const)("rejects %s without consuming a valid result", (_, mutate) => {
    const { exchange } = setup();
    const input = result(); mutate(input);
    expect(() => exchange.submit(input)).toThrow();
    expect(exchange.getResult()).toEqual({ status: "pending" });
    expect(exchange.submit(result()).status).toBe("proposal_received");
  });

  it("rejects approval instructions, oversized payloads, and malformed JSON", () => {
    const { exchange } = setup();
    expect(() => exchange.submit({ ...result(), approve: true })).toThrow("invalid_result");
    expect(() => exchange.submit({ ...result(), summary: "x".repeat(70_000) })).toThrow("result_too_large");
    expect(() => exchange.submit("broken-json")).toThrow("invalid_result");
  });

  it("enforces a server-owned call budget", () => {
    const { exchange } = setup();
    for (let i = 0; i < 24; i++) exchange.readSource(path);
    expect(() => exchange.readSource(path)).toThrow("call_budget_exhausted");
  });

  it("clones accepted results so callers cannot mutate the receipt or proposal", () => {
    const { exchange } = setup();
    const input = result(); const receipt = exchange.submit(input);
    input.edits[0].content = "mutated";
    Object.assign(receipt, { applied: true });
    expect(exchange.getResult()).toMatchObject({ receipt: { applied: false },
      proposal: { edits: [{ content: after }] } });
  });
});

describe("10B-1b: shared evidence checks", () => {
  it("accepts a natural quote from a CRLF source (review item b)", () => {
    const crlf = "const config = {\r\n  productionBrowserSourceMaps: true,\r\n};\r\nexport default config;\r\n";
    const exchange = createIntelligenceExchange({
      identity, host: "codex", files: [{ path, content: crlf }], instruction: "x",
      expiresAt: 2_000, now: () => 1_000, currentIdentity: () => identity, validateEdit: () => false,
    });
    const receipt = exchange.submit({ ...result(), status: "needs_human", edits: [],
      citations: [{ path, sourceHash: sourceHash(crlf), startLine: 2, endLine: 2, quote: "  productionBrowserSourceMaps: true," }] });
    expect(receipt.status).toBe("needs_human");
  });
});
