import { beforeEach, describe, expect, it, vi } from "vitest";

// 103 (Felipe 2026-10-15): only the customer, signed in on ShipLock's own
// page, turns agent pull requests on or off. A token cannot.
const mocks = vi.hoisted(() => ({ pro: vi.fn(), rpc: vi.fn() }));
vi.mock("@/lib/deep/proGate", () => ({ requireProUser: mocks.pro }));
vi.mock("@/lib/supabase", () => ({ getSupabaseAdmin: () => ({ rpc: mocks.rpc }) }));

import { DELETE, POST } from "./route";
import { AGENT_PRS_ACK } from "@/lib/agentPrs";

const REPO = "33333333-3333-4333-8333-333333333333";
const send = (handler: typeof POST, body: unknown, origin = "https://shiplock.dev") =>
  handler(new Request("https://shiplock.dev/api/intelligence/agent-prs", { method: "POST", headers: { origin }, body: JSON.stringify(body) }));

beforeEach(() => {
  vi.clearAllMocks();
  mocks.pro.mockResolvedValue({ userId: "u1" });
  mocks.rpc.mockResolvedValue({ data: "grant-1", error: null });
});

describe("/api/intelligence/agent-prs", () => {
  it("turns it on only with the current acknowledgement", async () => {
    expect((await send(POST, { repositoryId: REPO, acknowledgement: AGENT_PRS_ACK })).status).toBe(200);
    expect(mocks.rpc).toHaveBeenCalledWith("grant_agent_prs", { p_user: "u1", p_repository: REPO, p_ack: AGENT_PRS_ACK });
    expect((await send(POST, { repositoryId: REPO })).status).toBe(400);
    expect((await send(POST, { repositoryId: REPO, acknowledgement: "agent-prs-v0" })).status).toBe(400);
    expect(mocks.rpc).toHaveBeenCalledTimes(1);
  });

  it("turns it off", async () => {
    mocks.rpc.mockResolvedValue({ data: null, error: null });
    expect((await send(DELETE, { repositoryId: REPO })).status).toBe(200);
    expect(mocks.rpc).toHaveBeenCalledWith("revoke_agent_prs", { p_user: "u1", p_repository: REPO });
  });

  it("refuses a repository the account has not selected", async () => {
    mocks.rpc.mockResolvedValue({ data: null, error: { message: "repository unavailable" } });
    expect((await send(POST, { repositoryId: REPO, acknowledgement: AGENT_PRS_ACK })).status).toBe(409);
  });

  it("needs a signed-in customer", async () => {
    mocks.pro.mockResolvedValue(null);
    expect((await send(POST, { repositoryId: REPO, acknowledgement: AGENT_PRS_ACK })).status).toBe(401);
    expect(mocks.rpc).not.toHaveBeenCalled();
  });
});
