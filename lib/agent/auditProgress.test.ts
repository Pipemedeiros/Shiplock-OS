import { describe, expect, it } from "vitest";
import { auditProgress } from "./auditProgress";

// A running audit shows its steps as they happen (Felipe 2026-10-06: the user
// has to SEE something being done). Progress is best effort: it never fails
// or slows the audit, and writes land in order so an older trace never
// replaces a newer one.
describe("audit progress", () => {
  it("writes the trace so far after each step, in order", async () => {
    const seen: string[][] = [];
    const progress = auditProgress(async (trace) => { seen.push(trace.map((s) => s.label)); });
    progress.wrote([{ time: "0s", label: "a" }]);
    progress.wrote([{ time: "0s", label: "a" }, { time: "1s", label: "b" }]);
    await progress.flush();
    expect(seen).toEqual([["a"], ["a", "b"]]);
  });

  it("copies the trace, so a later step cannot change what an earlier write sent", async () => {
    const seen: number[] = [];
    let release!: () => void;
    const gate = new Promise<void>((r) => { release = r; });
    const progress = auditProgress(async (trace) => { await gate; seen.push(trace.length); });
    const trace = [{ time: "0s", label: "a" }];
    progress.wrote(trace);
    trace.push({ time: "1s", label: "b" });
    release();
    await progress.flush();
    expect(seen).toEqual([1]);
  });

  it("never throws when a write fails, and keeps writing later steps", async () => {
    const seen: string[] = [];
    let first = true;
    const progress = auditProgress(async (trace) => {
      if (first) { first = false; throw new Error("network"); }
      seen.push(trace[trace.length - 1].label);
    });
    progress.wrote([{ time: "0s", label: "a" }]);
    progress.wrote([{ time: "0s", label: "a" }, { time: "1s", label: "b" }]);
    await expect(progress.flush()).resolves.toBeUndefined();
    expect(seen).toEqual(["b"]);
  });

  it("skips writes queued behind a slow one, keeping only the newest", async () => {
    const seen: number[] = [];
    let release!: () => void;
    const gate = new Promise<void>((r) => { release = r; });
    let calls = 0;
    const progress = auditProgress(async (trace) => { calls++; if (calls === 1) await gate; seen.push(trace.length); });
    progress.wrote([{ time: "0s", label: "a" }]);
    progress.wrote([{ time: "0s", label: "a" }, { time: "1s", label: "b" }]);
    progress.wrote([{ time: "0s", label: "a" }, { time: "1s", label: "b" }, { time: "2s", label: "c" }]);
    release();
    await progress.flush();
    expect(seen).toEqual([1, 3]);
  });
});
