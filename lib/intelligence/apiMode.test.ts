import { beforeEach, describe, expect, it, vi } from "vitest";

const state = vi.hoisted(() => ({ view: vi.fn(), submit: vi.fn(), key: vi.fn(), file: vi.fn(), create: vi.fn(), clientKeys: [] as string[] }));
vi.mock("./tasks", () => ({ getIntelligenceTask: state.view, submitIntelligenceResult: state.submit }));
vi.mock("./credential", () => ({ loadApiKey: state.key }));
vi.mock("@/lib/deep/github", () => ({ getFile: state.file }));
vi.mock("@anthropic-ai/sdk", () => {
  class APIError extends Error { status: number; constructor(status: number, message: string) { super(message); this.status = status; } }
  class Anthropic {
    static APIError = APIError;
    messages = { create: state.create };
    constructor(options: { apiKey: string }) { state.clientKeys.push(options.apiKey); }
  }
  return { default: Anthropic };
});

import Anthropic from "@anthropic-ai/sdk";
import { runApiModeTask } from "./apiMode";

const ids = { taskId: "11111111-1111-4111-8111-111111111111", tenantId: "22222222-2222-4222-8222-222222222222",
  repositoryId: "33333333-3333-4333-8333-333333333333", commit: "a".repeat(40) };
const view = { identity: ids, host: "api", repository: "acme/app", instruction: "Review.", status: "pending",
  sources: [{ path: "app/api/x/route.ts", sourceHash: "b".repeat(64) }] };
const input = { userId: ids.tenantId, taskId: ids.taskId, token: "gh", fullName: "acme/app", runTokenBudget: 50_000 };
const customerKey = "sk-ant-api03-" + "C".repeat(60);
const answer = (text: string, usage = { input_tokens: 1200, output_tokens: 300 }) =>
  ({ model: "claude-opus-5", stop_reason: "end_turn", usage, content: [{ type: "text", text }] });
const modelResult = { version: 1, identity: { ...ids, connectionEpoch: "x", attempt: 9 }, host: "codex", model: "made-up",
  status: "needs_human", summary: "Ownership check missing.", citations: [], edits: [], usage: { inputTokens: 1, outputTokens: 1 } };

beforeEach(() => {
  vi.clearAllMocks(); state.clientKeys.length = 0;
  process.env.ANTHROPIC_API_KEY = "sk-ant-SHIPLOCK-OWN-KEY-must-never-be-used";
  state.view.mockResolvedValue(view);
  state.key.mockResolvedValue({ apiKey: customerKey, epoch: "e".repeat(64) });
  state.file.mockResolvedValue("export async function GET() {}\n");
  state.submit.mockResolvedValue({ outcome: "accepted" });
  state.create.mockResolvedValue(answer(JSON.stringify(modelResult)));
});

describe("API-key mode (10B-2e-2)", () => {
  it("calls the model only with the customer's key and records the API's own usage", async () => {
    expect(await runApiModeTask(input)).toBe("answered");
    expect(state.clientKeys).toEqual([customerKey]);
    const request = state.create.mock.calls[0][0];
    expect(request.model).toBe("claude-opus-5");
    expect(request.max_tokens).toBeLessThanOrEqual(8000);
    expect(JSON.stringify(request)).toContain("app/api/x/route.ts");
    const submitted = state.submit.mock.calls[0][2];
    // Identity, host, model, and usage are ShipLock's observations, not the model's claims.
    expect(submitted.identity).toEqual(ids);
    expect(submitted.host).toBe("api");
    expect(submitted.model).toBe("claude-opus-5");
    expect(submitted.usage).toEqual({ inputTokens: 1200, outputTokens: 300 });
  });

  it("never runs on ShipLock's key: no saved key means an honest unavailable result and no call", async () => {
    state.key.mockResolvedValue(null);
    expect(await runApiModeTask(input)).toBe("unavailable");
    expect(state.create).not.toHaveBeenCalled();
    expect(state.clientKeys).toEqual([]);
    expect(state.submit.mock.calls[0][2]).toMatchObject({ status: "unavailable", reason: "host_offline", citations: [], edits: [], usage: null });
  });

  it("does not spend again on a task that is no longer pending", async () => {
    state.view.mockResolvedValue({ ...view, status: "needs_human" });
    expect(await runApiModeTask(input)).toBe("skipped");
    expect(state.create).not.toHaveBeenCalled();
    state.view.mockResolvedValue(null);
    expect(await runApiModeTask(input)).toBe("skipped");
  });

  it("refuses to call when the run budget cannot cover the files plus an answer", async () => {
    state.file.mockResolvedValue("x".repeat(200_000));
    expect(await runApiModeTask({ ...input, runTokenBudget: 10_000 })).toBe("unavailable");
    expect(state.create).not.toHaveBeenCalled();
    expect(state.submit.mock.calls[0][2]).toMatchObject({ status: "unavailable", reason: "quota_exhausted" });
  });

  it("maps rate limits and credit exhaustion to quota_exhausted and other API errors to host_offline, without retrying", async () => {
    const APIError = (Anthropic as unknown as { APIError: new (s: number, m: string) => Error }).APIError;
    state.create.mockRejectedValueOnce(new APIError(429, "rate limited"));
    expect(await runApiModeTask(input)).toBe("unavailable");
    expect(state.submit.mock.calls[0][2]).toMatchObject({ reason: "quota_exhausted" });
    state.create.mockRejectedValueOnce(new APIError(400, "You have reached your specified API usage limits"));
    await runApiModeTask(input);
    expect(state.submit.mock.calls[1][2]).toMatchObject({ reason: "quota_exhausted" });
    state.create.mockRejectedValueOnce(new APIError(401, "invalid x-api-key"));
    await runApiModeTask(input);
    expect(state.submit.mock.calls[2][2]).toMatchObject({ reason: "host_offline" });
    expect(state.create).toHaveBeenCalledTimes(3);
  });

  it("records a malformed or rejected answer as unavailable, keeping the tokens it cost", async () => {
    state.create.mockResolvedValue(answer("not json", { input_tokens: 900, output_tokens: 50 }));
    expect(await runApiModeTask(input)).toBe("unavailable");
    expect(state.submit.mock.calls[0][2]).toMatchObject({ status: "unavailable", reason: "unsupported", usage: { inputTokens: 900, outputTokens: 50 } });
    state.submit.mockReset();
    state.create.mockResolvedValue(answer(JSON.stringify(modelResult)));
    state.submit.mockRejectedValueOnce(new Error("source_changed")).mockResolvedValueOnce({ outcome: "accepted" });
    expect(await runApiModeTask(input)).toBe("unavailable");
    expect(state.submit.mock.calls[1][2]).toMatchObject({ status: "unavailable", reason: "unsupported", usage: { inputTokens: 1200, outputTokens: 300 } });
  });
});
