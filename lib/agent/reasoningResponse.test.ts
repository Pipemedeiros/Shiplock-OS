import { beforeEach, describe, expect, it, vi } from "vitest";
import { proposeAttacks } from "./attack";
import { buildCoverage } from "./audit";
import { collectRoutes } from "@/lib/graph/routeInventory";
import { detectStack } from "./stack";

const { create } = vi.hoisted(() => ({ create: vi.fn() }));
vi.mock("@anthropic-ai/sdk", () => {
  class Client {
    messages = { create };
    static APIConnectionTimeoutError = class extends Error {};
  }
  return { default: Client };
});

const files = [{ path: "app/api/invoices/route.ts", content: `
  export async function GET() {
    return Response.json(await prisma.invoice.findMany());
  }
` }];
const stack = detectStack(files);
const input = {
  routes: collectRoutes(files), stack, tables: ["invoice"],
  files: files.map((file) => file.path),
};
const finding = {
  entry: "/api/invoices", attackClass: "missing_authentication",
  title: "Anonymous callers can read invoices",
  consequence: "Invoice data can be read without signing in.",
  citedFiles: [files[0].path], citedTables: ["invoice"],
};

beforeEach(() => { create.mockReset(); });

async function respond(text: string, stop_reason = "end_turn") {
  create.mockResolvedValue({ content: [{ type: "text", text }], stop_reason,
    usage: { input_tokens: 1, output_tokens: 1 } });
  return proposeAttacks(input);
}

describe("reasoning response integrity (no provider requests)", () => {
  it.each(["[]", "```json\n[]\n```"])("accepts a valid empty answer: %s", async (text) => {
    const result = await respond(text);
    expect(result).toMatchObject({ admitted: [], rejected: [], skipped: false, truncated: false, parseFailed: false });
  });

  it.each(["", "No issues found.", "[broken", "{}"])("discloses malformed output: %s", async (text) => {
    const result = await respond(text);
    expect(result).toMatchObject({ admitted: [], skipped: false, truncated: false, parseFailed: true });
    const notes = buildCoverage(stack, false, 0, false, 0, 0, [], result.skipped,
      result.truncated, input.routes, false, [], result.parseFailed);
    expect(notes.some((note) => note.effect.includes("not a clean result"))).toBe(true);
  });

  it("preserves a guarded finding recovered from malformed output", async () => {
    const result = await respond(`[${JSON.stringify(finding)}, broken`);
    expect(result.parseFailed).toBe(true);
    expect(result.admitted).toHaveLength(1);
  });

  it("keeps a complete nonempty answer valid", async () => {
    const result = await respond(JSON.stringify([finding]));
    expect(result.parseFailed).toBe(false);
    expect(result.admitted).toHaveLength(1);
  });

  it("keeps truncated salvage distinct from malformed complete output", async () => {
    const result = await respond(`[${JSON.stringify(finding)}, {`, "max_tokens");
    expect(result).toMatchObject({ skipped: false, truncated: true, parseFailed: false });
    expect(result.admitted).toHaveLength(1);
  });

  it("discloses truncation even when no object is recoverable", async () => {
    expect(await respond("[{", "max_tokens")).toMatchObject({
      admitted: [], skipped: false, truncated: true, parseFailed: false,
    });
  });

  it("keeps transport failure distinct from a completed answer", async () => {
    create.mockRejectedValue(new Error("provider unavailable"));
    expect(await proposeAttacks(input)).toMatchObject({ skipped: true, skipReason: "model call failed: provider unavailable" });
  });
});
