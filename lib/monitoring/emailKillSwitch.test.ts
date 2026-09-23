import { beforeEach, describe, expect, it, vi } from "vitest";

// Email stays globally off (EMAIL_ALERTS_ENABLED=false) until Felipe approves
// delivery and cost. The weekly digest and traffic threat alerts used to send
// regardless; neither may send while the switch is off. A traffic judgment is
// still recorded, because the graph reads it as "this source was judged".
const state = vi.hoisted(() => ({ enabled: { value: false }, send: vi.fn(), insert: vi.fn(), recent: vi.fn() }));
vi.mock("@/lib/access", () => ({ get EMAIL_ALERTS_ENABLED() { return state.enabled.value; } }));
vi.mock("@/lib/email", () => ({ sendEmail: state.send }));
vi.mock("@/lib/supabase", () => ({ getSupabaseAdmin: () => ({ from: () => {
  const q: Record<string, unknown> = {};
  for (const m of ["select", "eq", "gte", "limit", "update", "order", "in", "is", "not"]) q[m] = () => q;
  q.insert = state.insert;
  q.maybeSingle = async () => ({ data: null, error: null });
  q.single = async () => ({ data: null, error: null });
  q.then = (resolve: (v: unknown) => unknown) => resolve(state.recent());
  return q;
} }) }));

import { sendThreatAlert } from "@/lib/traffic/alerts";
import { sendWeeklyDigest } from "./digest";

beforeEach(() => {
  vi.clearAllMocks();
  state.enabled.value = false;
  state.send.mockResolvedValue(true);
  state.insert.mockResolvedValue({ error: null });
  state.recent.mockReturnValue({ data: [], error: null, count: 3 });
});

describe("email kill switch (parked until Felipe approves delivery and cost)", () => {
  it("sends no weekly digest while email is off", async () => {
    expect(await sendWeeklyDigest("u1", "founder@example.com", null)).toBe(false);
    expect(state.send).not.toHaveBeenCalled();
  });

  it("sends no threat email while off, but still records the traffic judgment", async () => {
    await sendThreatAlert("u1", "founder@example.com", "src-1", { action: "block", reason: "credential stuffing" } as never);
    expect(state.send).not.toHaveBeenCalled();
    expect(state.insert).toHaveBeenCalledWith(expect.objectContaining({ user_id: "u1", source_id: "src-1", action: "block" }));
  });

  it("sends the threat email when the switch is on", async () => {
    state.enabled.value = true;
    await sendThreatAlert("u1", "founder@example.com", "src-2", { action: "block", reason: "credential stuffing" } as never);
    expect(state.send).toHaveBeenCalledOnce();
  });
});
