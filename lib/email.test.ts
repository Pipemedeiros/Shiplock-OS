import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

const sendMock = vi.fn();
vi.mock("resend", () => ({
  Resend: class {
    emails = { send: sendMock };
  },
}));

const { sendEmail } = await import("./email");

const msg = { to: "a@b.com", subject: "s", text: "t" };

describe("sendEmail", () => {
  const prevKey = process.env.RESEND_API_KEY;
  const prevFrom = process.env.RESEND_FROM_EMAIL;

  beforeEach(() => {
    sendMock.mockReset();
    process.env.RESEND_API_KEY = "re_test";
    process.env.RESEND_FROM_EMAIL = "noreply@shiplock.dev";
  });

  afterEach(() => {
    process.env.RESEND_API_KEY = prevKey;
    process.env.RESEND_FROM_EMAIL = prevFrom;
  });

  it("returns true when Resend confirms the send", async () => {
    sendMock.mockResolvedValue({ data: { id: "e1" }, error: null });
    expect(await sendEmail(msg, "test")).toBe(true);
  });

  it("passes an HTML body through with its text fallback (Q29), and omits html when there is none", async () => {
    sendMock.mockResolvedValue({ data: { id: "e2" }, error: null });
    await sendEmail({ ...msg, html: "<p>hi</p>" }, "test");
    expect(sendMock).toHaveBeenLastCalledWith(expect.objectContaining({ text: msg.text, html: "<p>hi</p>" }));
    await sendEmail(msg, "test");
    expect(sendMock.mock.calls.at(-1)?.[0]).not.toHaveProperty("html");
  });

  // The case every previous call site was blind to: the Resend SDK RESOLVES on
  // an API error rather than throwing, so `.catch()` and try/catch never fired.
  it("returns false when Resend resolves with an error instead of throwing", async () => {
    sendMock.mockResolvedValue({
      data: null,
      error: { name: "validation_error", message: "domain is not verified" },
    });
    expect(await sendEmail(msg, "test")).toBe(false);
  });

  it("returns false on a network-level throw", async () => {
    sendMock.mockRejectedValue(new Error("ECONNRESET"));
    expect(await sendEmail(msg, "test")).toBe(false);
  });

  it("never throws, so a mail outage cannot fail a monitoring pass", async () => {
    sendMock.mockRejectedValue(new Error("boom"));
    await expect(sendEmail(msg, "test")).resolves.toBe(false);
  });

  // A missing key must not look like delivery.
  it("returns false and does not call Resend when config is missing", async () => {
    delete process.env.RESEND_API_KEY;
    expect(await sendEmail(msg, "test")).toBe(false);
    expect(sendMock).not.toHaveBeenCalled();
  });

  it("returns false when the from address is unset", async () => {
    delete process.env.RESEND_FROM_EMAIL;
    expect(await sendEmail(msg, "test")).toBe(false);
    expect(sendMock).not.toHaveBeenCalled();
  });
});
