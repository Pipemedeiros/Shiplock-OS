import { NextRequest } from "next/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const proxyMocks = vi.hoisted(() => ({ getClaims: vi.fn(), observe: vi.fn() }));
vi.mock("@/lib/traffic/selfObserve", () => ({ observeSelf: proxyMocks.observe }));
vi.mock("@supabase/ssr", () => ({
  createServerClient: vi.fn(() => ({ auth: { getClaims: proxyMocks.getClaims } })),
}));

import { config, proxy } from "./proxy";

beforeEach(() => {
  proxyMocks.getClaims.mockReset().mockResolvedValue({ data: null, error: null });
});

afterEach(() => { vi.unstubAllEnvs(); });

describe("Section 4 / Step 4A: Next.js proxy boundary", () => {
  it("adds a per-request CSP without contacting auth for an anonymous page", async () => {
    const response = await proxy(new NextRequest("https://shiplock.dev/"));
    const csp = response.headers.get("content-security-policy");

    expect(proxyMocks.getClaims).not.toHaveBeenCalled();
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

  it("uses exact Supabase HTTP and realtime origins with a fresh nonce in production", async () => {
    vi.stubEnv("NODE_ENV", "production");
    vi.stubEnv("NEXT_PUBLIC_SUPABASE_URL", "https://project.supabase.co/a-path?ignored=yes");
    vi.resetModules();
    const { proxy: productionProxy } = await import("./proxy");
    const first = await productionProxy(new NextRequest("https://shiplock.dev/"));
    const second = await productionProxy(new NextRequest("https://shiplock.dev/"));
    const csp = first.headers.get("content-security-policy") ?? "";
    const directives = new Map(csp.split("; ").map(d => [d.split(" ")[0], d]));
    expect(csp).not.toContain("*");
    expect(directives.get("connect-src")).toContain("https://project.supabase.co");
    expect(directives.get("connect-src")).toContain("wss://project.supabase.co");
    expect(csp).not.toContain("a-path");
    for (const name of ["script-src", "frame-src", "object-src", "base-uri"]) {
      expect(directives.get(name)).not.toMatch(/unsafe-inline|unsafe-eval|\*/);
    }
    const script = directives.get("script-src") ?? "";
    expect(script.match(/https:\/\/[^ ]+/g)).toEqual(["https://accounts.google.com/gsi/client"]);
    const nonce = first.headers.get("x-middleware-request-x-nonce");
    expect(nonce).toBeTruthy();
    expect(script).toContain(`'nonce-${nonce}'`);
    expect(nonce).not.toBe(second.headers.get("x-middleware-request-x-nonce"));
    expect(first.headers.get("x-middleware-request-content-security-policy")).toBe(csp);
  });

  // A missing or malformed Supabase URL must not take every page down; the
  // policy just names no Supabase origin (fail closed for that host).
  it("still serves a CSP when the Supabase URL is missing or malformed", async () => {
    for (const value of ["", "not a url"]) {
      vi.stubEnv("NEXT_PUBLIC_SUPABASE_URL", value);
      const csp = (await proxy(new NextRequest("https://shiplock.dev/"))).headers.get("content-security-policy") ?? "";
      expect(csp).toContain("default-src 'self'");
      expect(csp).not.toMatch(/supabase/);
    }
    vi.unstubAllEnvs();
  });

  // Dogfooding (Felipe 2026-10-01): ShipLock observes its own traffic after
  // the response, never in front of it.
  it("hands each request to self-observation off the response path", async () => {
    const waitUntil = vi.fn();
    proxyMocks.observe.mockResolvedValue(undefined);
    const request = new NextRequest("https://shiplock.dev/dashboard");
    await proxy(request, { waitUntil } as never);
    expect(proxyMocks.observe).toHaveBeenCalledWith(request);
    expect(waitUntil).toHaveBeenCalledTimes(1);
  });

  it("refreshes auth only when a Supabase session cookie exists", async () => {
    const request = new NextRequest("https://shiplock.dev/dashboard", {
      headers: { cookie: "sb-project-auth-token.0=fixture" },
    });

    await proxy(request);

    expect(proxyMocks.getClaims).toHaveBeenCalledOnce();
  });

  it("keeps static assets outside the proxy matcher", () => {
    expect(config.matcher[0]).toContain("_next/static");
    expect(config.matcher[0]).toContain("_next/image");
    expect(config.matcher[0]).toContain("svg|png|jpg|jpeg|gif|webp");
  });
});
