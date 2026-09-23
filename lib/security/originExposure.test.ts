import { describe, expect, it, vi } from "vitest";
import {
  detectEdge,
  edgeProviderFromHeaders,
  analyzeOriginPosture,
  checkNoEdge,
  checkOriginLeak,
  collectOriginPosture,
  edgeProviderFor,
  isBehindEdgeCname,
} from "./originExposure";

const posture = (over: Partial<Parameters<typeof checkOriginLeak>[0]> = {}) => ({
  domain: "example.com",
  webIps: ["104.18.1.5"],
  cnames: [],
  mxHosts: [],
  mxIps: [],
  headers: { server: "cloudflare" },
  ...over,
});

describe("edge detection", () => {
  it("recognises major edge networks by address", () => {
    expect(edgeProviderFor("76.76.21.9")).toBe("Vercel");
    expect(edgeProviderFor("104.18.1.5")).toBe("Cloudflare");
    expect(edgeProviderFor("151.101.1.1")).toBe("Fastly");
  });

  it("returns null for an ordinary address", () => {
    expect(edgeProviderFor("203.0.113.7")).toBeNull();
  });

  it("recognises an edge CNAME whatever the address", () => {
    expect(isBehindEdgeCname(["cname.vercel-dns.com."])).toBe("cname.vercel-dns.com");
    expect(isBehindEdgeCname(["d123.cloudfront.net"])).toContain("cloudfront.net");
    expect(isBehindEdgeCname(["some.random.host"])).toBeNull();
  });
});

describe("origin leak via mail records", () => {
  // The classic: a mail server cannot sit behind an HTTP CDN, so its address is
  // real infrastructure, published in DNS by design.
  it("flags web and mail resolving to the same address behind a CDN", () => {
    const out = checkOriginLeak(
      posture({ webIps: ["104.18.1.5", "203.0.113.7"], mxIps: ["203.0.113.7"] })
    );
    expect(out).toHaveLength(1);
    expect(out[0].severity).toBe("WARNING");
    expect(out[0].consequence).toContain("without passing through Cloudflare");
  });

  it("is silent when mail is on separate infrastructure", () => {
    expect(checkOriginLeak(posture({ mxIps: ["198.51.100.9"] }))).toEqual([]);
  });

  it("is silent when there is no mail at all", () => {
    expect(checkOriginLeak(posture())).toEqual([]);
  });

  // Nothing to bypass means nothing to report.
  it("does NOT fire when the app is not behind an edge network", () => {
    expect(
      checkOriginLeak(posture({ webIps: ["203.0.113.7"], mxIps: ["203.0.113.7"], headers: { server: "nginx" } }))
    ).toEqual([]);
  });

  it("ignores private addresses", () => {
    expect(checkOriginLeak(posture({ webIps: ["10.0.0.1"], mxIps: ["10.0.0.1"] }))).toEqual([]);
  });

  // We say the door exists; closing it is theirs.
  it("does not claim we can fix it", () => {
    const out = checkOriginLeak(posture({ webIps: ["104.18.1.5", "203.0.113.7"], mxIps: ["203.0.113.7"] }));
    expect(out[0].consequence).toContain("not something we can do for you");
  });
});

describe("no edge network", () => {
  it("notes a directly-served app at INFO", () => {
    const out = checkNoEdge(posture({ webIps: ["203.0.113.7"], headers: { server: "nginx" } }));
    expect(out).toHaveLength(1);
    expect(out[0].severity).toBe("INFO");
  });

  // Serving directly is a normal choice, not a fault.
  it("declines to call it a mistake or recommend a purchase", () => {
    const out = checkNoEdge(posture({ webIps: ["203.0.113.7"], headers: { server: "nginx" } }));
    expect(out[0].consequence).toContain("normal choice");
    expect(out[0].consequence).toContain("If you are already behind something we did not recognise, ignore this");
  });

  // The honest boundary, stated to the customer rather than only in our docs.
  it("says plainly that volumetric absorption is not ours", () => {
    const out = checkNoEdge(posture({ webIps: ["203.0.113.7"], headers: { server: "nginx" } }));
    expect(out[0].consequence).toContain("not something we can do from inside your app");
    expect(out[0].consequence).toContain("credential stuffing");
  });

  it("is silent when behind a recognised edge", () => {
    expect(checkNoEdge(posture())).toEqual([]);
    expect(checkNoEdge(posture({ webIps: ["203.0.113.7"], cnames: ["x.vercel-dns.com"], headers: { server: "nginx" } }))).toEqual([]);
  });

  it("is silent when nothing resolves", () => {
    expect(checkNoEdge(posture({ webIps: [], headers: { server: "nginx" } }))).toEqual([]);
  });
});

describe("collectOriginPosture", () => {
  const resolver = (over: Record<string, unknown> = {}) => ({
    resolve4: vi.fn().mockResolvedValue(["104.18.1.5"]),
    resolveCname: vi.fn().mockResolvedValue([]),
    resolveMx: vi.fn().mockResolvedValue([]),
    ...over,
  });

  it("gathers web, cname and mail addresses", async () => {
    const dns = resolver({
      resolveMx: vi.fn().mockResolvedValue([{ exchange: "mail.example.com", priority: 10 }]),
    });
    dns.resolve4 = vi
      .fn()
      .mockResolvedValueOnce(["104.18.1.5"])
      .mockResolvedValue(["203.0.113.7"]);
    const out = (await collectOriginPosture("example.com", dns))!;
    expect(out.webIps).toEqual(["104.18.1.5"]);
    expect(out.mxIps).toEqual(["203.0.113.7"]);
  });

  // A domain with no mail is ordinary.
  it("tolerates every lookup failing individually", async () => {
    const dns = resolver({ resolveMx: vi.fn().mockRejectedValue(new Error("ENODATA")) });
    const out = await collectOriginPosture("example.com", dns);
    expect(out?.mxIps).toEqual([]);
  });

  it("returns null when the domain does not resolve at all", async () => {
    const dns = resolver({
      resolve4: vi.fn().mockRejectedValue(new Error("ENOTFOUND")),
      resolveCname: vi.fn().mockRejectedValue(new Error("ENOTFOUND")),
    });
    expect(await collectOriginPosture("nope.invalid", dns)).toBeNull();
  });
});

describe("analyzeOriginPosture", () => {
  it("reports the leak and stays quiet about the edge when one exists", () => {
    const out = analyzeOriginPosture(
      posture({ webIps: ["104.18.1.5", "203.0.113.7"], mxIps: ["203.0.113.7"] })
    );
    expect(out.map((x) => x.id)).toEqual(["origin:mx_reveals_origin"]);
  });

  it("is silent on a clean setup", () => {
    expect(analyzeOriginPosture(posture())).toEqual([]);
  });
});


// Address ranges rot. This one rotted before it shipped: shiplock.dev and
// vercel.com BOTH resolve outside the documented Vercel ranges, so an IP-first
// check told the host most of this ICP uses that it had no edge protection.
describe("edge detection prefers headers, because address ranges go stale", () => {
  it("identifies providers from their response headers", () => {
    expect(edgeProviderFromHeaders({ "x-vercel-id": "iad1::abc" })).toBe("Vercel");
    expect(edgeProviderFromHeaders({ "cf-ray": "8a1b::" })).toBe("Cloudflare");
    expect(edgeProviderFromHeaders({ server: "Vercel" })).toBe("Vercel");
    expect(edgeProviderFromHeaders({ "x-amz-cf-id": "z" })).toBe("CloudFront");
    expect(edgeProviderFromHeaders({ "x-nf-request-id": "z" })).toBe("Netlify");
  });

  it("is case-insensitive about header names", () => {
    expect(edgeProviderFromHeaders({ "X-Vercel-Id": "iad1::abc" })).toBe("Vercel");
  });

  it("returns null for an ordinary server header", () => {
    expect(edgeProviderFromHeaders({ server: "nginx" })).toBeNull();
    expect(edgeProviderFromHeaders({})).toBeNull();
  });

  // The real regression: an address outside the known ranges, behind Vercel.
  it("detects Vercel from headers even when the address is unrecognised", () => {
    expect(detectEdge(posture({ webIps: ["216.198.79.1"], headers: { server: "Vercel" } }))).toBe("Vercel");
  });

  it("falls back to CNAME, then to address ranges", () => {
    expect(detectEdge(posture({ webIps: ["203.0.113.7"], cnames: ["x.vercel-dns.com"], headers: {} }))).toContain("vercel-dns");
    expect(detectEdge(posture({ webIps: ["104.18.1.5"], headers: {} }))).toBe("Cloudflare");
  });

  // Unknown must never read as "no protection".
  it("says NOTHING about missing edge protection when the app could not be fetched", () => {
    expect(checkNoEdge(posture({ webIps: ["203.0.113.7"], headers: undefined }))).toEqual([]);
  });

  it("still reports no edge when we fetched it and found none", () => {
    expect(checkNoEdge(posture({ webIps: ["203.0.113.7"], headers: { server: "nginx" } }))).toHaveLength(1);
  });
});

describe("collectOriginPosture — 1E-1 readability", () => {
  const dnsError = (code: string) => Object.assign(new Error(code), { code });
  const resolver = (over: Record<string, unknown> = {}) => ({
    resolve4: vi.fn().mockResolvedValue(["104.18.1.5"]),
    resolveCname: vi.fn().mockRejectedValue(dnsError("ENODATA")),
    resolveMx: vi.fn().mockRejectedValue(dnsError("ENODATA")),
    ...over,
  });

  it("treats DNS absence as read", async () => {
    const unread: string[] = [];
    await collectOriginPosture("example.com", resolver(), undefined, unread);
    expect(unread).toEqual([]);
  });

  it("marks origin findings unread when a lookup fails for another reason", async () => {
    const unread: string[] = [];
    await collectOriginPosture("example.com", resolver({ resolveMx: vi.fn().mockRejectedValue(dnsError("ETIMEOUT")) }), undefined, unread);
    expect(unread).toEqual(["origin:"]);
  });
});
