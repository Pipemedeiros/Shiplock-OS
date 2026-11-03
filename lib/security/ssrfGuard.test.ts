import { describe, expect, it, vi, beforeEach } from "vitest";
import { isPrivateOrReservedIp, assertPublicHttpsUrl, guardedFetch, SsrfBlockedError, type HostResolver } from "./ssrfGuard";

describe("isPrivateOrReservedIp", () => {
  it("blocks loopback", () => {
    expect(isPrivateOrReservedIp("127.0.0.1")).toBe(true);
    expect(isPrivateOrReservedIp("127.255.255.255")).toBe(true);
  });

  it("blocks the cloud metadata / link-local range", () => {
    // 169.254.169.254 is the AWS/GCP/Azure instance-metadata address — the
    // single highest-value SSRF target (credential theft).
    expect(isPrivateOrReservedIp("169.254.169.254")).toBe(true);
  });

  it("blocks RFC1918 private ranges", () => {
    expect(isPrivateOrReservedIp("10.0.0.1")).toBe(true);
    expect(isPrivateOrReservedIp("172.16.0.1")).toBe(true);
    expect(isPrivateOrReservedIp("172.31.255.255")).toBe(true);
    expect(isPrivateOrReservedIp("192.168.1.1")).toBe(true);
  });

  it("does not block adjacent public ranges (no over-blocking)", () => {
    expect(isPrivateOrReservedIp("172.32.0.1")).toBe(false); // just outside 172.16/12
    expect(isPrivateOrReservedIp("172.15.255.255")).toBe(false);
    expect(isPrivateOrReservedIp("8.8.8.8")).toBe(false);
    expect(isPrivateOrReservedIp("1.1.1.1")).toBe(false);
  });

  it("blocks CGNAT (100.64.0.0/10)", () => {
    expect(isPrivateOrReservedIp("100.64.0.1")).toBe(true);
    expect(isPrivateOrReservedIp("100.127.255.255")).toBe(true);
    expect(isPrivateOrReservedIp("100.63.255.255")).toBe(false);
  });

  it("blocks multicast and reserved space", () => {
    expect(isPrivateOrReservedIp("224.0.0.1")).toBe(true);
    expect(isPrivateOrReservedIp("255.255.255.255")).toBe(true);
  });

  it("blocks IPv6 loopback, unspecified, link-local, and unique-local", () => {
    expect(isPrivateOrReservedIp("::1")).toBe(true);
    expect(isPrivateOrReservedIp("::")).toBe(true);
    expect(isPrivateOrReservedIp("fe80::1")).toBe(true);
    expect(isPrivateOrReservedIp("fd00::1")).toBe(true);
  });

  it("unwraps IPv4-mapped IPv6 addresses before checking", () => {
    // A DNS response of ::ffff:169.254.169.254 is the same metadata target
    // wearing an IPv6 wrapper — a naive IPv6-only check would miss this.
    expect(isPrivateOrReservedIp("::ffff:169.254.169.254")).toBe(true);
    expect(isPrivateOrReservedIp("::ffff:8.8.8.8")).toBe(false);
  });
});

function fakeResolver(map: Record<string, string[]>): HostResolver {
  return {
    async lookup(hostname) {
      if (!(hostname in map)) throw new Error(`no fake DNS entry for ${hostname}`);
      return map[hostname];
    },
  };
}

describe("assertPublicHttpsUrl", () => {
  it("allows a URL resolving only to public addresses", async () => {
    const resolver = fakeResolver({ "app.example.com": ["93.184.216.34"] });
    await expect(assertPublicHttpsUrl("https://app.example.com/", resolver)).resolves.toBeUndefined();
  });

  it("rejects a URL resolving to cloud metadata", async () => {
    const resolver = fakeResolver({ "attacker.example.com": ["169.254.169.254"] });
    await expect(assertPublicHttpsUrl("https://attacker.example.com/", resolver)).rejects.toBeInstanceOf(
      SsrfBlockedError
    );
  });

  it("rejects a hostname that is itself a private-IP literal", async () => {
    const resolver = fakeResolver({ "10.0.0.5": ["10.0.0.5"] });
    await expect(assertPublicHttpsUrl("https://10.0.0.5/", resolver)).rejects.toBeInstanceOf(SsrfBlockedError);
  });

  it("rejects a DNS-rebinding hostname if ANY resolved address is private", async () => {
    // A hostname legitimately resolving to a public AND a private address
    // (or configured to rotate between them) must be blocked outright —
    // there is no safe way to "pick the public one" and trust the choice
    // holds for the actual request.
    const resolver = fakeResolver({ "rebind.example.com": ["93.184.216.34", "127.0.0.1"] });
    await expect(assertPublicHttpsUrl("https://rebind.example.com/", resolver)).rejects.toBeInstanceOf(
      SsrfBlockedError
    );
  });

  it("rejects non-https protocols even to a public host", async () => {
    const resolver = fakeResolver({ "app.example.com": ["93.184.216.34"] });
    await expect(assertPublicHttpsUrl("http://app.example.com/", resolver)).rejects.toBeInstanceOf(
      SsrfBlockedError
    );
  });

  it("rejects an unresolvable hostname rather than treating it as safe", async () => {
    const resolver = fakeResolver({});
    await expect(assertPublicHttpsUrl("https://does-not-resolve.example/", resolver)).rejects.toBeInstanceOf(
      SsrfBlockedError
    );
  });

  it("rejects a malformed URL", async () => {
    const resolver = fakeResolver({});
    await expect(assertPublicHttpsUrl("not a url", resolver)).rejects.toBeInstanceOf(SsrfBlockedError);
  });
});

describe("guardedFetch — the actual attack this guard exists to stop", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("PROVES the vulnerability existed: a public host redirecting to an internal address must not be followed", async () => {
    // This is the exact shape of ShipLock's own real gap: appUrl is a
    // customer-controlled URL that gets fetch(..., { redirect: "follow" })'d
    // server-side (bundleAudit.ts, originExposure.ts) and is RE-FETCHED
    // automatically forever via monitored_app_url on every 48h pass
    // (lib/monitoring/run.ts). A customer who owns a public domain can 302 it
    // to any internal address the ShipLock function's network can reach.
    const resolver = fakeResolver({
      "attacker-controlled.example.com": ["93.184.216.34"], // resolves public — passes the naive check
      "169.254.169.254": ["169.254.169.254"], // the redirect target
    });

    const fetchMock = vi.fn(async (url: string | URL) => {
      const href = url.toString();
      if (href.startsWith("https://attacker-controlled.example.com")) {
        return new Response(null, { status: 302, headers: { location: "https://169.254.169.254/latest/meta-data/" } });
      }
      // If this branch is ever reached, the guard failed to stop the hop —
      // the test below asserts fetchMock is never called with the internal
      // target at all.
      return new Response("iam-credentials-would-be-here", { status: 200 });
    });
    vi.stubGlobal("fetch", fetchMock);

    await expect(
      guardedFetch("https://attacker-controlled.example.com/", {}, { resolver })
    ).rejects.toBeInstanceOf(SsrfBlockedError);

    // The internal host must never have been requested at all.
    expect(fetchMock).not.toHaveBeenCalledWith(
      expect.objectContaining({ href: expect.stringContaining("169.254.169.254") }),
      expect.anything()
    );
    const calledUrls = fetchMock.mock.calls.map((c) => c[0]!.toString());
    expect(calledUrls.some((u) => u.includes("169.254.169.254"))).toBe(false);
  });

  it("follows a redirect chain that stays entirely public", async () => {
    const resolver = fakeResolver({
      "old.example.com": ["93.184.216.34"],
      "new.example.com": ["93.184.216.35"],
    });
    const fetchMock = vi.fn(async (url: string | URL) => {
      const href = url.toString();
      if (href.startsWith("https://old.example.com")) {
        return new Response(null, { status: 301, headers: { location: "https://new.example.com/" } });
      }
      return new Response("ok", { status: 200 });
    });
    vi.stubGlobal("fetch", fetchMock);

    const res = await guardedFetch("https://old.example.com/", {}, { resolver });
    expect(res.status).toBe(200);
    expect(await res.text()).toBe("ok");
  });

  it("gives up after maxRedirects rather than following forever", async () => {
    const resolver = fakeResolver({ "loop.example.com": ["93.184.216.34"] });
    const fetchMock = vi.fn(async () => new Response(null, { status: 302, headers: { location: "https://loop.example.com/" } }));
    vi.stubGlobal("fetch", fetchMock);

    await expect(
      guardedFetch("https://loop.example.com/", {}, { resolver, maxRedirects: 2 })
    ).rejects.toBeInstanceOf(SsrfBlockedError);
  });
});

describe("guardedFetch — cancellation", () => {
  it("does not resolve or request a hop once the caller signal has aborted", async () => {
    const lookup = vi.fn(async () => ["93.184.216.34"]);
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    const caller = new AbortController();
    caller.abort(new Error("collector timed out"));
    await expect(guardedFetch("https://app.example.com/", { signal: caller.signal }, { resolver: { lookup } }))
      .rejects.toThrow("collector timed out");
    expect(lookup).not.toHaveBeenCalled();
    expect(fetchMock).not.toHaveBeenCalled();
    vi.unstubAllGlobals();
  });
});
