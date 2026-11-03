import { beforeEach, describe, expect, it, vi } from "vitest";

// A bundle read that failed is not a bundle that no longer leaks.
const guarded = vi.hoisted(() => vi.fn());
vi.mock("@/lib/security/ssrfGuard", async (original) => ({
  ...await original<typeof import("./ssrfGuard")>(), guardedFetch: guarded,
}));

import { auditShippedBundle } from "./bundleAudit";

const page = (scripts: number) =>
  `<html>${Array.from({ length: scripts }, (_, i) => `<script src="/_next/static/chunks/c${i}.js"></script>`).join("")}</html>`;
const ok = (body: string, status = 200) => new Response(body, { status });
const read = () => ({ pageRead: false, pagesRead: 0, scriptsSeen: 0, scriptsRead: 0, paths: new Set<string>(), requests: new Set<string>() });

beforeEach(() => { guarded.mockReset(); });

describe("auditShippedBundle readability", () => {
  it("marks the whole bundle family unread when the page cannot be read", async () => {
    guarded.mockRejectedValue(new Error("ETIMEDOUT"));
    const unread: string[] = [];
    expect(await auditShippedBundle("https://app.example.com", undefined, unread)).toEqual([]);
    expect(unread).toEqual(["bundle:"]);
  });

  it("marks secrets and source maps unread when a chunk cannot be read", async () => {
    guarded.mockImplementation(async (url: string) =>
      url.endsWith("c1.js") ? ok("", 502) : url.endsWith(".js") ? ok("var a=1;") : ok(page(2)));
    const unread: string[] = [];
    await auditShippedBundle("https://app.example.com", undefined, unread);
    expect([...new Set(unread)].sort()).toEqual(["bundle:shipped_secret:", "bundle:source_map_exposed:"]);
  });

  it("marks secrets and source maps unread when more chunks exist than are read", async () => {
    guarded.mockImplementation(async (url: string) => url.endsWith(".js") ? ok("var a=1;") : ok(page(49)));
    const unread: string[] = [];
    await auditShippedBundle("https://app.example.com", undefined, unread);
    expect([...new Set(unread)].sort()).toEqual(["bundle:shipped_secret:", "bundle:source_map_exposed:"]);
  });

  it("marks a source map unread when its fetch fails", async () => {
    guarded.mockImplementation(async (url: string) => {
      if (url.endsWith(".map")) throw new Error("ECONNRESET");
      if (url.endsWith(".js")) return ok("var a=1;\n//# sourceMappingURL=c0.js.map");
      return ok(page(1));
    });
    const unread: string[] = [];
    await auditShippedBundle("https://app.example.com", undefined, unread);
    expect(unread).toEqual(["bundle:source_map_exposed:"]);
  });

  it("marks nothing unread when every read succeeded", async () => {
    guarded.mockImplementation(async (url: string) => url.endsWith(".js") ? ok("var a=1;") : ok(page(2)));
    const unread: string[] = [];
    await auditShippedBundle("https://app.example.com", undefined, unread);
    expect(unread).toEqual([]);
  });
});

// The same scripts say which paths the live site calls, and how many of
// them were read, so a partial read is never mistaken for the whole bundle.
describe("auditShippedBundle called paths", () => {
  it("records the paths the page and each read chunk name, with what was read", async () => {
    guarded.mockImplementation(async (url: string) =>
      url.endsWith("c0.js") ? ok('fetch("/api/orders/"+id)') : url.endsWith("c1.js") ? ok("", 502)
        : ok(page(2).replace("</html>", '<script>fetch("/api/me")</script></html>')));
    const shipped = read();
    await auditShippedBundle("https://app.example.com", undefined, [], shipped);
    expect({ ...shipped, paths: [...shipped.paths].sort(), requests: [...shipped.requests].sort() }).toEqual({ pageRead: true,
      pagesRead: 1, scriptsSeen: 2, scriptsRead: 1, paths: ["/api/me", "/api/orders/"], requests: ["/api/me", "/api/orders/"] });
  });

  it("records nothing read when the page cannot be read", async () => {
    guarded.mockRejectedValue(new Error("ETIMEDOUT"));
    const shipped = read();
    await auditShippedBundle("https://app.example.com", undefined, [], shipped);
    expect(shipped.pageRead).toBe(false);
  });
});

// Outside view v2: a home page loads only its own chunks, so the pass also
// reads the pages a visitor reaches by a link from it, the way a click would.
describe("auditShippedBundle linked pages", () => {
  const home = '<html><a href="/pricing">p</a><a href="/blog">b</a><a href="/logout">o</a><a href="/api/export">x</a>'
    + '<a href="https://other.example.com/x">o</a><script src="/_next/static/chunks/shared.js"></script></html>';
  const fetched = () => guarded.mock.calls.map(([u]) => String(u));

  it("reads each linked page and its new scripts once, never an API, sign-out or other host", async () => {
    guarded.mockImplementation(async (url: string) => {
      if (url.endsWith("/pricing")) return ok('<script src="/_next/static/chunks/shared.js"></script><script src="/_next/static/chunks/pricing.js"></script>');
      if (url.endsWith("/blog")) return ok('<script src="/_next/static/chunks/blog.js"></script>');
      if (url.endsWith("pricing.js")) return ok('fetch("/api/plans")');
      if (url.endsWith(".js")) return ok("var a=1;");
      return ok(home);
    });
    const shipped = read();
    const unread: string[] = [];
    await auditShippedBundle("https://app.example.com", undefined, unread, shipped);
    expect(fetched().filter((u) => u.endsWith("shared.js"))).toHaveLength(1);
    expect(fetched().some((u) => /logout|api\/export|other\.example/.test(u))).toBe(false);
    expect(shipped).toMatchObject({ pagesRead: 3, scriptsSeen: 3, scriptsRead: 3 });
    expect(shipped.requests.has("/api/plans")).toBe(true);
    expect(unread).toEqual([]);
  });

  it("finds a secret that only a linked page ships", async () => {
    guarded.mockImplementation(async (url: string) => {
      if (url.endsWith("/pricing")) return ok('<script src="/_next/static/chunks/pricing.js"></script>');
      if (url.endsWith("pricing.js")) return ok('const k="sk_live_' + "a".repeat(24) + '"');
      if (url.endsWith(".js")) return ok("var a=1;");
      if (url.endsWith("/blog")) return ok("<html></html>");
      return ok(home);
    });
    const ids = (await auditShippedBundle("https://app.example.com", undefined, [])).map((f) => f.id);
    expect(ids).toContain("bundle:shipped_secret:stripe_live_secret");
  });

  it("treats a page that answers an anonymous visitor with an error as read, and a failed one as unread", async () => {
    guarded.mockImplementation(async (url: string) => {
      if (url.endsWith("/pricing")) return ok("sign in", 401);
      if (url.endsWith("/blog")) throw new Error("ECONNRESET");
      if (url.endsWith(".js")) return ok("var a=1;");
      return ok(home);
    });
    const shipped = read();
    const unread: string[] = [];
    await auditShippedBundle("https://app.example.com", undefined, unread, shipped);
    expect(shipped.pagesRead).toBe(2);
    expect([...new Set(unread)].sort()).toEqual(["bundle:shipped_secret:", "bundle:source_map_exposed:"]);
  });

  it("does not read the scripts of a page that redirected to another host", async () => {
    guarded.mockImplementation(async (url: string) => {
      if (url.endsWith("/pricing")) {
        const res = ok('<script src="https://login.example.net/_next/static/chunks/sso.js"></script><script src="/_next/static/chunks/sso.js"></script>');
        Object.defineProperty(res, "url", { value: "https://login.example.net/pricing" });
        return res;
      }
      if (url.endsWith("/blog")) return ok("<html></html>");
      if (url.endsWith(".js")) return ok("var a=1;");
      return ok(home);
    });
    await auditShippedBundle("https://app.example.com", undefined, []);
    expect(fetched().some((u) => u.includes("sso.js"))).toBe(false);
  });
});

describe("auditShippedBundle pacing", () => {
  it("never has more than 8 scripts in flight and still reads all 48", async () => {
    let inFlight = 0, peak = 0;
    guarded.mockImplementation(async (url: string) => {
      if (!url.endsWith(".js")) return ok(page(48));
      inFlight++; peak = Math.max(peak, inFlight);
      await new Promise((r) => setTimeout(r, 2));
      inFlight--;
      return ok("var a=1;");
    });
    const shipped = read();
    const unread: string[] = [];
    await auditShippedBundle("https://app.example.com", undefined, unread, shipped);
    expect(peak).toBe(8);
    expect(shipped.scriptsRead).toBe(48);
    expect(unread).toEqual([]);
  });
});
