import { NextRequest } from "next/server";
import { beforeEach, describe, expect, it, vi } from "vitest";

const proxyMocks = vi.hoisted(() => ({ getUser: vi.fn() }));
vi.mock("@supabase/ssr", () => ({
  createServerClient: vi.fn(() => ({ auth: { getUser: proxyMocks.getUser } })),
}));

import { config, proxy } from "./proxy";

beforeEach(() => {
  proxyMocks.getUser.mockReset().mockResolvedValue({ data: { user: null }, error: null });
});

describe("Section 4 / Step 4A: Next.js proxy boundary", () => {
  it("adds a per-request CSP without contacting auth for an anonymous page", async () => {
    const response = await proxy(new NextRequest("https://shiplock.dev/"));
    const csp = response.headers.get("content-security-policy");

    expect(proxyMocks.getUser).not.toHaveBeenCalled();
    expect(csp).toContain("default-src 'self'");
    expect(csp).toContain("'strict-dynamic'");
    expect(csp).toContain("frame-ancestors 'none'");
    expect(response.headers.get("x-middleware-request-x-nonce")).toBeTruthy();
  });

  // Google One Tap (Felipe 2026-09-30): Google's script is loaded by our nonced
  // bundle (strict-dynamic), and its prompt frame, styles and FedCM calls come
  // from accounts.google.com. Nothing else is widened.
  it("allows Google One Tap and nothing broader", async () => {
    const csp = (await proxy(new NextRequest("https://shiplock.dev/"))).headers.get("content-security-policy") ?? "";
    const directive = (name: string) => csp.split("; ").find((d) => d.startsWith(`${name} `)) ?? "";
    expect(directive("frame-src")).toContain("https://accounts.google.com");
    expect(directive("connect-src")).toContain("https://accounts.google.com");
    expect(directive("style-src")).toContain("https://accounts.google.com/gsi/style");
    expect(directive("script-src")).toContain("https://accounts.google.com/gsi/client");
    expect(csp).not.toMatch(/https:\/\/\*\.google\.com|'unsafe-inline'[^;]*script|script-src[^;]*'unsafe-inline'/);
  });

  it("refreshes auth only when a Supabase session cookie exists", async () => {
    const request = new NextRequest("https://shiplock.dev/dashboard", {
      headers: { cookie: "sb-project-auth-token.0=fixture" },
    });

    await proxy(request);

    expect(proxyMocks.getUser).toHaveBeenCalledOnce();
  });

  it("keeps static assets outside the proxy matcher", () => {
    expect(config.matcher[0]).toContain("_next/static");
    expect(config.matcher[0]).toContain("_next/image");
    expect(config.matcher[0]).toContain("svg|png|jpg|jpeg|gif|webp");
  });
});
