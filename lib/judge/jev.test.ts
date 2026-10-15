import { describe, expect, it } from "vitest";
import { JEV_MODEL, jevRequest, jevVerdict, type JudgeEvidence } from "./jev";

// P7 (Felipe 2026-10-15: "implement Jev as best as you can"). JEV answers
// typed questions with calibrated probabilities. This module only builds the
// request from evidence ShipLock already holds and turns the answer into a
// keep or review decision; it makes no call (the developer harness does,
// scripts/jevClient.ts; product use waits on Felipe's lock decision).
const evidence: JudgeEvidence = {
  statement: "Anyone can delete any order by id.",
  files: [
    { path: "app/api/orders/[id]/route.ts", content: "export async function DELETE(req, { params }) {\n  await db.order.delete({ where: { id: params.id } });\n}" },
    { path: "middleware.ts", content: "export const config = { matcher: ['/dashboard/:path*'] };" },
  ],
  facts: ["The app has no sign-in anywhere."],
};

describe("jevRequest", () => {
  it("asks the labelers' two questions as yes or no, on the evidence they read", () => {
    const req = jevRequest(evidence);
    expect(req.model).toBe(JEV_MODEL);
    expect(Object.keys(req.questions).sort()).toEqual(["accurate", "real"]);
    expect(req.questions.accurate.type).toBe("noul");
    expect(req.questions.real.type).toBe("noul");
    expect(req.state).toEqual({
      statement: "Anyone can delete any order by id.",
      files: [
        { path: "app/api/orders/[id]/route.ts", numbered: "1: export async function DELETE(req, { params }) {\n2:   await db.order.delete({ where: { id: params.id } });\n3: }" },
        { path: "middleware.ts", numbered: "1: export const config = { matcher: ['/dashboard/:path*'] };" },
      ],
      facts: ["The app has no sign-in anywhere."],
    });
  });

  it("carries Felipe's rule for apps with no accounts (2026-10-15)", () => {
    const real = JSON.stringify(jevRequest(evidence).questions.real);
    expect(real).toMatch(/no accounts/);
    expect(real).toMatch(/demo or has a single operator/);
  });

  it("bounds the evidence so a request stays well under the API's limits", () => {
    const big = { ...evidence, files: Array.from({ length: 40 }, (_, i) => ({ path: `f${i}.ts`, content: "x\n".repeat(20_000) })) };
    expect(Buffer.byteLength(JSON.stringify(jevRequest(big)))).toBeLessThan(400_000);
  });
});

describe("jevVerdict", () => {
  const answer = (accurate: number, real: number) => ({ model: "jev-1", answers: {
    accurate: { type: "noul" as const, noul: accurate }, real: { type: "noul" as const, noul: real } }, usage: { input_tokens: 1, output_tokens: 1 } });

  it("keeps a finding both answers support, and reports the joint probability", () => {
    expect(jevVerdict(answer(0.9, 0.8), { keepAtLeast: 0.5 })).toEqual({ pAccurate: 0.9, pReal: 0.8, p: 0.72, keep: true });
  });
  it("sends a finding below the threshold to review, never drops it", () => {
    expect(jevVerdict(answer(0.9, 0.4), { keepAtLeast: 0.5 })).toMatchObject({ keep: false });
  });
  it("keeps the finding as it was when the answer is unreadable", () => {
    expect(jevVerdict({ model: "x", answers: {}, usage: { input_tokens: 0, output_tokens: 0 } }, { keepAtLeast: 0.5 })).toEqual({ pAccurate: null, pReal: null, p: null, keep: true });
  });
});
