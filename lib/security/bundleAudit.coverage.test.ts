import { beforeEach, describe, expect, it, vi } from "vitest";

// 1E-1: a bundle read that failed is not a bundle that no longer leaks.
const guarded = vi.hoisted(() => vi.fn());
vi.mock("@/lib/security/ssrfGuard", async (original) => ({
  ...await original<typeof import("./ssrfGuard")>(), guardedFetch: guarded,
}));

import { auditShippedBundle } from "./bundleAudit";

const page = (scripts: number) =>
  `<html>${Array.from({ length: scripts }, (_, i) => `<script src="/_next/static/chunks/c${i}.js"></script>`).join("")}</html>`;
const ok = (body: string, status = 200) => new Response(body, { status });

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
    guarded.mockImplementation(async (url: string) => url.endsWith(".js") ? ok("var a=1;") : ok(page(9)));
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
