import { describe, it, expect, vi, beforeEach } from "vitest";
import type { Finding } from "./findings";

// The contract this file guards: the dedup log is what suppresses re-alerting
// for 7 days, so it must only be written when the email actually went out.
// Writing it after a failed send marked a customer as notified when they were
// not — the finding stays open in every later snapshot, is filtered out as
// "recently alerted" on every subsequent pass, and no email is sent for a week.
// For a leaked service-role key that is a week of silence on the most urgent
// thing this product detects.

const sendEmailMock = vi.fn();
const insertMock = vi.fn();
const selectResult = vi.fn();

vi.mock("@/lib/email", () => ({ sendEmail: sendEmailMock }));
vi.mock("@/lib/supabase", () => ({
  getSupabaseAdmin: () => ({
    from: () => ({
      select: () => ({ eq: () => ({ gte: selectResult }) }),
      insert: (rows: unknown) => {
        insertMock(rows);
        return { then: (r: (v: unknown) => unknown) => r({ error: null }) };
      },
    }),
  }),
}));

const { sendNewFindingsAlert } = await import("./alerts");

const finding = (id: string): Finding => ({
  id,
  severity: "CRITICAL",
  title: `t-${id}`,
  consequence: `c-${id}`,
});

describe("sendNewFindingsAlert — dedup only on confirmed delivery", () => {
  beforeEach(() => {
    sendEmailMock.mockReset().mockResolvedValue(true);
    insertMock.mockReset();
    selectResult.mockReset().mockResolvedValue({ data: [] });
  });

  it("records dedup rows when the email sent", async () => {
    await sendNewFindingsAlert("u1", "a@b.com", [finding("rls:orders")]);
    expect(insertMock).toHaveBeenCalledTimes(1);
    expect(insertMock.mock.calls[0][0]).toEqual([
      { user_id: "u1", finding_id: "rls:orders" },
    ]);
  });

  it("does NOT record dedup rows when the email failed", async () => {
    sendEmailMock.mockResolvedValue(false);
    await sendNewFindingsAlert("u1", "a@b.com", [finding("service_role_key")]);
    expect(insertMock).not.toHaveBeenCalled();
  });

  it("leaves the finding eligible for the next pass after a failed send", async () => {
    sendEmailMock.mockResolvedValue(false);
    await sendNewFindingsAlert("u1", "a@b.com", [finding("service_role_key")]);

    // Next pass: nothing was recorded, so the same finding is offered again.
    sendEmailMock.mockResolvedValue(true);
    await sendNewFindingsAlert("u1", "a@b.com", [finding("service_role_key")]);

    expect(sendEmailMock).toHaveBeenCalledTimes(2);
    expect(insertMock).toHaveBeenCalledTimes(1);
  });

  it("still suppresses findings already alerted inside the window", async () => {
    selectResult.mockResolvedValue({ data: [{ finding_id: "rls:orders" }] });
    await sendNewFindingsAlert("u1", "a@b.com", [finding("rls:orders")]);
    expect(sendEmailMock).not.toHaveBeenCalled();
    expect(insertMock).not.toHaveBeenCalled();
  });

  it("sends for the genuinely-new subset when some are already alerted", async () => {
    selectResult.mockResolvedValue({ data: [{ finding_id: "old" }] });
    await sendNewFindingsAlert("u1", "a@b.com", [finding("old"), finding("new")]);

    expect(sendEmailMock).toHaveBeenCalledTimes(1);
    expect(insertMock.mock.calls[0][0]).toEqual([{ user_id: "u1", finding_id: "new" }]);
  });

  it("does nothing at all when there are no new findings", async () => {
    await sendNewFindingsAlert("u1", "a@b.com", []);
    expect(sendEmailMock).not.toHaveBeenCalled();
  });
});
