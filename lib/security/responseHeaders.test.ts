import { beforeEach, describe, expect, it, vi } from "vitest";

// Two hardening headers on the founder's live home page, read as a visitor
// gets them. INFO only: a missing header is a gap, not a confirmed exposure.
const guarded = vi.hoisted(() => vi.fn());
vi.mock("@/lib/security/ssrfGuard", async (original) => ({ ...await original<typeof import("./ssrfGuard")>(), guardedFetch: guarded }));
import { auditResponseHeaders, judgeHeaders } from "./responseHeaders";

const html = (headers: Record<string, string>, status = 200, url = "https://app.example.com/") => {
  const res = new Response("<html></html>", { status, headers: { "content-type": "text/html; charset=utf-8", ...headers } });
  Object.defineProperty(res, "url", { value: url });
  return res;
};
beforeEach(() => guarded.mockReset());

describe("judgeHeaders", () => {
  it("finds nothing when frames are refused and HTTPS is pinned", () => {
    expect(judgeHeaders({ "x-frame-options": "DENY", "strict-transport-security": "max-age=63072000" }, true)).toEqual([]);
    expect(judgeHeaders({ "content-security-policy": "default-src 'self'; frame-ancestors 'self'", "strict-transport-security": "max-age=1" }, true)).toEqual([]);
  });

  it("flags a page any site can frame, including a wildcard or report-only rule", () => {
    const ids = (h: Record<string, string>) => judgeHeaders({ "strict-transport-security": "max-age=1", ...h }, true).map((f) => f.id);
    expect(ids({})).toEqual(["headers:frame_protection_missing"]);
    expect(ids({ "content-security-policy": "frame-ancestors *" })).toEqual(["headers:frame_protection_missing"]);
    expect(ids({ "content-security-policy-report-only": "frame-ancestors 'none'" })).toEqual(["headers:frame_protection_missing"]);
    expect(ids({ "x-frame-options": "ALLOWALL" })).toEqual(["headers:frame_protection_missing"]);
  });

  it("flags HTTPS that is not pinned, only on an https answer", () => {
    expect(judgeHeaders({ "x-frame-options": "SAMEORIGIN" }, true).map((f) => f.id)).toEqual(["headers:hsts_missing"]);
    expect(judgeHeaders({ "x-frame-options": "SAMEORIGIN", "strict-transport-security": "max-age=0" }, true).map((f) => f.id)).toEqual(["headers:hsts_missing"]);
    expect(judgeHeaders({ "x-frame-options": "SAMEORIGIN" }, false)).toEqual([]);
  });

  it("is INFO, says what to add, and uses no dashes", () => {
    for (const f of judgeHeaders({}, true)) {
      expect(f.severity).toBe("INFO");
      expect(`${f.title} ${f.consequence}`).not.toMatch(/ [-–—] /);
    }
  });
});

describe("auditResponseHeaders", () => {
  it("judges the home page a visitor gets", async () => {
    guarded.mockResolvedValue(html({}));
    const unread: string[] = [];
    expect((await auditResponseHeaders("https://app.example.com", undefined, unread)).map((f) => f.id))
      .toEqual(["headers:frame_protection_missing", "headers:hsts_missing"]);
    expect(unread).toEqual([]);
  });

  it("leaves the family unread on a failed read, an error answer or a page that is not HTML", async () => {
    for (const answer of [() => Promise.reject(new Error("ETIMEDOUT")), () => Promise.resolve(html({}, 503)),
      () => Promise.resolve(new Response("{}", { status: 200, headers: { "content-type": "application/json" } }))]) {
      guarded.mockImplementationOnce(answer);
      const unread: string[] = [];
      expect(await auditResponseHeaders("https://app.example.com", undefined, unread)).toEqual([]);
      expect(unread).toEqual(["headers:"]);
    }
  });
});
