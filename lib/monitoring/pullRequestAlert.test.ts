import { beforeEach, describe, expect, it, vi } from "vitest";

// The email a paid customer gets when a pull request introduces a risk.
const mocks = vi.hoisted(() => ({ send: vi.fn(), enabled: { value: true } }));
vi.mock("@/lib/email", () => ({ sendEmail: mocks.send }));
vi.mock("@/lib/access", () => ({ get EMAIL_ALERTS_ENABLED() { return mocks.enabled.value; } }));

import { sendPullRequestAlert } from "./pullRequestAlert";

const review = {
  repository: "acme/app", number: 9, title: "Add orders API",
  findings: [{ severity: "CRITICAL" as const, title: "/api/orders reaches orders without resolving a caller", file: "app/api/orders/route.ts" }],
};

beforeEach(() => {
  vi.clearAllMocks();
  mocks.enabled.value = true;
  mocks.send.mockResolvedValue(true);
  process.env.NEXT_PUBLIC_APP_URL = "https://shiplock.dev";
});

describe("sendPullRequestAlert", () => {
  it("names the risk and links to the dashboard to review and fix before merge", async () => {
    expect(await sendPullRequestAlert("founder@example.com", review)).toBe("sent");
    const [message, context] = mocks.send.mock.calls[0];
    expect(context).toBe("pull-request");
    expect(message.to).toBe("founder@example.com");
    expect(message.subject).toBe("ShipLock: pull request #9 on acme/app introduces a security risk");
    expect(message.text).toContain("/api/orders reaches orders without resolving a caller");
    expect(message.text).toContain("app/api/orders/route.ts");
    expect(message.text).toContain("https://shiplock.dev/dashboard/prs");
    expect(`${message.subject}${message.text}`).not.toMatch(/malicious|[—–]/i);
  });

  it("sends nothing while email alerts are parked", async () => {
    mocks.enabled.value = false;
    expect(await sendPullRequestAlert("founder@example.com", review)).toBe("skipped");
    expect(mocks.send).not.toHaveBeenCalled();
  });

  it("reports an unconfirmed send so the job retries", async () => {
    mocks.send.mockResolvedValue(false);
    expect(await sendPullRequestAlert("founder@example.com", review)).toBe("failed");
  });
});
