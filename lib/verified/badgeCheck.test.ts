import { describe, it, expect, vi, afterEach } from "vitest";
import { checkBadgeInstalled } from "./badgeCheck";

const TOKEN = "abc123def456";

function htmlResponse(body: string, status = 200) {
  return new Response(body, {
    status,
    headers: { "content-type": "text/html; charset=utf-8" },
  });
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("checkBadgeInstalled", () => {
  it("finds a badge linking to the customer's own report", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        htmlResponse(`<html><body><a href="https://shiplock.dev/verified/${TOKEN}">Secured</a></body></html>`)
      )
    );
    const res = await checkBadgeInstalled("https://customer.app", TOKEN);
    expect(res.state).toBe("installed");
  });

  it("matches on the token path even when linked via another host", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(htmlResponse(`<a href="/verified/${TOKEN}">badge</a>`))
    );
    const res = await checkBadgeInstalled("https://customer.app", TOKEN);
    expect(res.state).toBe("installed");
  });

  it("flags a badge pointing at somebody else's report", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(htmlResponse(`<a href="/verified/someoneelsestoken99">badge</a>`))
    );
    const res = await checkBadgeInstalled("https://customer.app", TOKEN);
    expect(res.state).toBe("not_found");
    expect(res.detail).toMatch(/different report/i);
  });

  it("reports not_found when no badge is present", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(htmlResponse("<html><body>hi</body></html>")));
    const res = await checkBadgeInstalled("https://customer.app", TOKEN);
    expect(res.state).toBe("not_found");
  });

  // Fail-soft: never accuse a paying customer of not installing it because
  // their site was slow, down, or hostile to bots.
  it("returns unknown when the site errors", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(htmlResponse("nope", 503)));
    const res = await checkBadgeInstalled("https://customer.app", TOKEN);
    expect(res.state).toBe("unknown");
  });

  it("returns unknown when the fetch throws", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("ECONNREFUSED")));
    const res = await checkBadgeInstalled("https://customer.app", TOKEN);
    expect(res.state).toBe("unknown");
  });

  it("returns unknown for a non-HTML response", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response("{}", { status: 200, headers: { "content-type": "application/json" } })
      )
    );
    const res = await checkBadgeInstalled("https://customer.app", TOKEN);
    expect(res.state).toBe("unknown");
  });

  it("returns unknown for an unusable app URL", async () => {
    const res = await checkBadgeInstalled("not a url", TOKEN);
    expect(res.state).toBe("unknown");
  });

  it("refuses non-web protocols", async () => {
    const res = await checkBadgeInstalled("file:///etc/passwd", TOKEN);
    expect(res.state).toBe("unknown");
  });
});
