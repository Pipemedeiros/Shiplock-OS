import { describe, expect, it } from "vitest";
import { judgeAnswer } from "./attack";
import { buildCoverage } from "./audit";
import { collectRoutes } from "@/lib/graph/routeInventory";
import { detectStack } from "./stack";

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

// Whatever host wrote the answer (the customer's agent, or the developer
// corpus harness), it is read and judged the same way.
function respond(text: string, stop_reason = "end_turn") {
  return judgeAnswer(input, text, stop_reason, "customer-agent");
}

describe("reasoning response integrity (no provider requests)", () => {
  it.each(["[]", "```json\n[]\n```"])("accepts a valid empty answer: %s", async (text) => {
    const result = respond(text);
    expect(result).toMatchObject({ admitted: [], rejected: [], skipped: false, truncated: false, parseFailed: false });
  });

  it.each(["", "No issues found.", "[broken", "{}"])("discloses malformed output: %s", async (text) => {
    const result = respond(text);
    expect(result).toMatchObject({ admitted: [], skipped: false, truncated: false, parseFailed: true });
    const notes = buildCoverage(stack, false, 0, false, 0, 0, [], result.skipped,
      result.truncated, input.routes, false, [], result.parseFailed);
    expect(notes.some((note) => note.effect.includes("not a clean result"))).toBe(true);
  });

  it("preserves a guarded finding recovered from malformed output", async () => {
    const result = respond(`[${JSON.stringify(finding)}, broken`);
    expect(result.parseFailed).toBe(true);
    expect(result.admitted).toHaveLength(1);
  });

  it("keeps a complete nonempty answer valid", async () => {
    const result = respond(JSON.stringify([finding]));
    expect(result.parseFailed).toBe(false);
    expect(result.admitted).toHaveLength(1);
  });

  it("keeps truncated salvage distinct from malformed complete output", async () => {
    const result = respond(`[${JSON.stringify(finding)}, {`, "max_tokens");
    expect(result).toMatchObject({ skipped: false, truncated: true, parseFailed: false });
    expect(result.admitted).toHaveLength(1);
  });

  it("discloses truncation even when no object is recoverable", async () => {
    expect(respond("[{", "max_tokens")).toMatchObject({
      admitted: [], skipped: false, truncated: true, parseFailed: false,
    });
  });
});
