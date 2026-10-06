import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { startAndWaitForAudit } from "./auditClient";

beforeEach(() => {
  vi.useFakeTimers();
  vi.stubGlobal("crypto", { randomUUID: () => "11111111-1111-4111-8111-111111111111" });
});
afterEach(() => { vi.useRealTimers(); vi.unstubAllGlobals(); });

it("starts once and follows the durable run to completion well under ten minutes", async () => {
  const states = [
    {status:"queued",trace:[],findings_count:0,entries_found:null},
    {status:"running",trace:[{time:"now",label:"Inventory"}],findings_count:0,entries_found:4},
    {status:"complete",trace:[{time:"now",label:"Done"}],findings_count:1,entries_found:4},
  ];
  const fetchMock = vi.fn()
    .mockResolvedValueOnce(new Response(JSON.stringify({runId:"22222222-2222-4222-8222-222222222222"}),{status:202}))
    .mockImplementation(() => Promise.resolve(new Response(JSON.stringify(states.shift()),{status:200})));
  vi.stubGlobal("fetch",fetchMock);
  const progress = vi.fn();
  const resultPromise = startAndWaitForAudit("acme/app",progress);
  await vi.advanceTimersByTimeAsync(2_000);
  const result = await resultPromise;
  expect(result.status).toBe("complete");
  expect(fetchMock).toHaveBeenCalledTimes(4);
  expect(fetchMock.mock.calls[0][0]).toBe("/api/audit");
  expect(JSON.parse(fetchMock.mock.calls[0][1].body)).toEqual({repository:"acme/app",requestId:"11111111-1111-4111-8111-111111111111"});
  expect(progress).toHaveBeenCalledTimes(3);
  expect(vi.getTimerCount()).toBe(0);
});

it("never turns a failed durable run into a completed onboarding step", async () => {
  vi.stubGlobal("fetch",vi.fn()
    .mockResolvedValueOnce(new Response(JSON.stringify({runId:"22222222-2222-4222-8222-222222222222"}),{status:202}))
    .mockResolvedValueOnce(new Response(JSON.stringify({status:"failed",trace:[],findings_count:0,entries_found:null}),{status:200})));
  await expect(startAndWaitForAudit("acme/app")).rejects.toThrow("stopped before it finished");
});

it("caps foreground waiting at ninety seconds rather than trapping onboarding", async () => {
  const fetchMock = vi.fn()
    .mockResolvedValueOnce(new Response(JSON.stringify({runId:"22222222-2222-4222-8222-222222222222"}),{status:202}))
    .mockImplementation(() => Promise.resolve(new Response(JSON.stringify({status:"queued",trace:[],findings_count:0,entries_found:null}),{status:200})));
  vi.stubGlobal("fetch",fetchMock);
  const promise = startAndWaitForAudit("acme/app");
  const assertion = expect(promise).rejects.toThrow("still queued");
  await vi.advanceTimersByTimeAsync(90_000);
  await assertion;
  expect(fetchMock).toHaveBeenCalledTimes(91);
});

it("says a run still working at the cap is running, not queued", async () => {
  vi.stubGlobal("fetch", vi.fn()
    .mockResolvedValueOnce(new Response(JSON.stringify({runId:"22222222-2222-4222-8222-222222222222"}),{status:202}))
    .mockImplementation(() => Promise.resolve(new Response(JSON.stringify({status:"running",trace:[{time:"1s",label:"412 files read"}],findings_count:0,entries_found:null}),{status:200}))));
  const promise = startAndWaitForAudit("acme/app");
  const assertion = expect(promise).rejects.toThrow("still running");
  await vi.advanceTimersByTimeAsync(90_000);
  await assertion;
});
