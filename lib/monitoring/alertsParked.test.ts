import { describe, expect, it, vi } from "vitest";
import type { Finding } from "./findings";

// Alerts are parked for the MVP. This asserts the park is real — not that the
// email failed, but that we never reached the mail path at all.
const sendEmailMock = vi.fn();
vi.mock("@/lib/email", () => ({ sendEmail: sendEmailMock }));
vi.mock("@/lib/access", () => ({ EMAIL_ALERTS_ENABLED: false }));
vi.mock("@/lib/supabase", () => ({
  getSupabaseAdmin: () => {
    throw new Error("the admin client must not be reached while alerts are parked");
  },
}));

const { sendNewFindingsAlert } = await import("./alerts");

const finding = {
  id: "f1",
  severity: "CRITICAL",
  title: "Service role key submitted",
  consequence: "Full read and write on every table.",
} as unknown as Finding;

describe("sendNewFindingsAlert while alerts are parked", () => {
  it("sends nothing and never touches the dedup log", async () => {
    await expect(sendNewFindingsAlert("u1", "a@b.com", [finding])).resolves.toBeUndefined();
    expect(sendEmailMock).not.toHaveBeenCalled();
  });
});
