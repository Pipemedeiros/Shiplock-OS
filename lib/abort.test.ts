import { describe, expect, it } from "vitest";
import { requestSignal } from "./abort";

describe("requestSignal", () => {
  it("keeps the transport's own timeout when no caller signal is supplied", async () => {
    const signal = requestSignal(undefined, 5);
    expect(signal.aborted).toBe(false);
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(signal.aborted).toBe(true);
  });

  it("aborts as soon as the caller aborts, before the transport timeout", () => {
    const caller = new AbortController();
    const signal = requestSignal(caller.signal, 60_000);
    caller.abort(new Error("collector timed out"));
    expect(signal.aborted).toBe(true);
    expect((signal.reason as Error).message).toBe("collector timed out");
  });
});
