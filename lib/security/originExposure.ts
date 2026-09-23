import type { Severity } from "@/lib/types";
import { guardedFetch } from "@/lib/security/ssrfGuard";
import { requestSignal } from "@/lib/abort";
import { isAbsenceError } from "@/lib/security/emailAuth";

// D — origin exposure: is the customer's edge protection bypassable?
//
// We cannot absorb a volumetric attack and never will. That is positional
// rather than a matter of effort: our code runs INSIDE the customer's app, so by
// the time it executes the packet has already crossed the network, terminated
// TLS and woken a function. The cost is paid before we see it, and mitigation
// has to happen upstream of us.
//
// What we CAN do from here is the thing their edge provider cannot: check
// whether the protection they already have is reachable around.
//
// The failure is common and quiet. You put a CDN in front of your app, and the
// origin's own address stays resolvable somewhere — a leftover A record, a mail
// server on the same host, a staging subdomain. An attacker resolves that
// instead and connects to the origin directly, and every protection bought at
// the edge is simply not in the path. Nothing looks wrong from the outside:
// the site is up, the CDN is serving, the dashboard is green.
//
// This is a POSTURE check, not protection. We say the door exists; closing it is
// a firewall rule at their host. That distinction is in the copy, because
// implying we defend against DDoS would be claiming someone else's capability.

export interface OriginFinding {
  id: string;
  severity: Severity;
  title: string;
  consequence: string;
}

/** What a resolver must provide. Injected so every rule is unit-testable. */
export interface DnsResolver {
  resolve4(name: string): Promise<string[]>;
  resolveMx(name: string): Promise<{ exchange: string; priority: number }[]>;
  resolveCname(name: string): Promise<string[]>;
}

/**
 * Address ranges belonging to edge networks that terminate traffic for their
 * customers. An app resolving into one of these is behind that provider's
 * protection; anything else is very likely the origin itself.
 *
 * FALLBACK ONLY. Address ranges rot, and this list proved it immediately:
 * shiplock.dev and vercel.com itself both resolve outside the documented Vercel
 * ranges, so an IP-first check reported "no edge protection" for the host most
 * of this ICP actually uses. Response headers are the primary signal — an edge
 * network announces itself on every request, and that cannot go stale.
 */
const EDGE_PREFIXES: { prefix: string; provider: string }[] = [
  { prefix: "76.76.21.", provider: "Vercel" },
  { prefix: "76.76.19.", provider: "Vercel" },
  { prefix: "66.33.60.", provider: "Vercel" },
  { prefix: "104.16.", provider: "Cloudflare" },
  { prefix: "104.17.", provider: "Cloudflare" },
  { prefix: "104.18.", provider: "Cloudflare" },
  { prefix: "104.19.", provider: "Cloudflare" },
  { prefix: "104.20.", provider: "Cloudflare" },
  { prefix: "104.21.", provider: "Cloudflare" },
  { prefix: "172.64.", provider: "Cloudflare" },
  { prefix: "172.65.", provider: "Cloudflare" },
  { prefix: "172.66.", provider: "Cloudflare" },
  { prefix: "172.67.", provider: "Cloudflare" },
  { prefix: "162.159.", provider: "Cloudflare" },
  { prefix: "188.114.", provider: "Cloudflare" },
  { prefix: "99.83.", provider: "AWS Global Accelerator" },
  { prefix: "75.2.", provider: "AWS Global Accelerator" },
  { prefix: "13.32.", provider: "CloudFront" },
  { prefix: "13.35.", provider: "CloudFront" },
  { prefix: "151.101.", provider: "Fastly" },
  { prefix: "199.232.", provider: "Fastly" },
  { prefix: "35.241.", provider: "Google Cloud LB" },
  { prefix: "34.36.", provider: "Google Cloud LB" },
];

/** CNAME targets that indicate a managed edge, whatever the address resolves to. */
const EDGE_CNAME =
  /\.(vercel-dns\.com|vercel\.app|netlify\.app|cloudfront\.net|fastly\.net|azureedge\.net|pages\.dev|workers\.dev|herokudns\.com|ghs\.googlehosted\.com|awsglobalaccelerator\.com)\.?$/i;

/**
 * Edge providers identify themselves in response headers. This is the reliable
 * signal: it is emitted per request, it cannot drift the way an address range
 * does, and we already fetch the page for the bundle audit.
 */
const EDGE_HEADERS: { header: string; match?: RegExp; provider: string }[] = [
  { header: "x-vercel-id", provider: "Vercel" },
  { header: "cf-ray", provider: "Cloudflare" },
  { header: "x-amz-cf-id", provider: "CloudFront" },
  { header: "x-nf-request-id", provider: "Netlify" },
  { header: "x-served-by", match: /cache-|fastly/i, provider: "Fastly" },
  { header: "x-fastly-request-id", provider: "Fastly" },
  { header: "server", match: /^vercel$/i, provider: "Vercel" },
  { header: "server", match: /cloudflare/i, provider: "Cloudflare" },
  { header: "server", match: /netlify/i, provider: "Netlify" },
  { header: "server", match: /^awselb/i, provider: "AWS ELB" },
  { header: "via", match: /cloudfront/i, provider: "CloudFront" },
  { header: "x-akamai-transformed", provider: "Akamai" },
];

/** The edge provider named by response headers, if any. */
export function edgeProviderFromHeaders(headers: Record<string, string>): string | null {
  const lower: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) lower[k.toLowerCase()] = v;

  for (const entry of EDGE_HEADERS) {
    const value = lower[entry.header];
    if (value === undefined) continue;
    if (entry.match && !entry.match.test(value)) continue;
    return entry.provider;
  }
  return null;
}

export function edgeProviderFor(ip: string): string | null {
  for (const entry of EDGE_PREFIXES) {
    if (ip.startsWith(entry.prefix)) return entry.provider;
  }
  return null;
}

export function isBehindEdgeCname(cnames: string[]): string | null {
  for (const target of cnames) {
    if (EDGE_CNAME.test(target)) return target.replace(/\.$/, "");
  }
  return null;
}

/** Private and reserved ranges — never a real origin, and never a finding. */
function isNonRoutable(ip: string): boolean {
  return /^(10\.|127\.|0\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(ip);
}

export interface OriginPosture {
  domain: string;
  webIps: string[];
  cnames: string[];
  mxHosts: string[];
  mxIps: string[];
  /** Response headers from the app, when we could fetch them. */
  headers?: Record<string, string>;
}

/**
 * Which edge network fronts this app, by the most reliable signal available.
 *
 * Headers first, then CNAME, then address ranges. `undefined` headers mean we
 * could not fetch the app at all, which is different from fetching it and
 * finding no edge — and the callers below treat those differently.
 */
export function detectEdge(posture: OriginPosture): string | null {
  if (posture.headers) {
    const fromHeaders = edgeProviderFromHeaders(posture.headers);
    if (fromHeaders) return fromHeaders;
  }
  const fromCname = isBehindEdgeCname(posture.cnames);
  if (fromCname) return fromCname;
  return posture.webIps.map(edgeProviderFor).find((p): p is string => p !== null) ?? null;
}

/**
 * The finding: mail and web resolve to the same address.
 *
 * This is the classic leak and the most reliable one to detect. A mail server
 * cannot sit behind an HTTP CDN — it speaks SMTP — so its A record points at
 * real infrastructure. When that address is the same one serving the site, the
 * CDN in front of the site is decoration: the origin is published in the MX
 * record, which is public by design and which no amount of edge configuration
 * hides.
 */
export function checkOriginLeak(posture: OriginPosture): OriginFinding[] {
  const { domain, webIps, mxIps } = posture;

  const routableWeb = webIps.filter((ip) => !isNonRoutable(ip));
  if (routableWeb.length === 0) return [];

  const provider = detectEdge(posture);
  const shared = routableWeb.filter((ip) => mxIps.includes(ip));

  // Only meaningful if there IS an edge to bypass.
  if (provider && shared.length > 0) {
    return [
      {
        id: "origin:mx_reveals_origin",
        severity: "WARNING",
        title: `Your mail records point at the same server as your site`,
        consequence:
          `${domain} is served through ${provider}, but its mail records resolve to ${shared.join(", ")} — the same address serving the site. ` +
          `A mail server cannot sit behind an HTTP CDN, so its address is real infrastructure and it is published in DNS by design. Anyone can read it, connect to that address directly, and reach your app without passing through ${provider} at all. ` +
          `Everything you rely on ${provider} for — rate limiting, bot filtering, absorbing a flood — is only in the path for people who arrive the normal way. ` +
          `We are telling you the door exists; closing it is a firewall rule at your host that accepts traffic only from ${provider}'s ranges. That is not something we can do for you, and it is worth doing once.`,
      },
    ];
  }

  return [];
}

/**
 * Whether the app appears to sit behind any edge network at all.
 *
 * Reported at INFO and worded carefully. Plenty of perfectly good setups serve
 * directly from an origin, and a small app doing so is a reasonable choice
 * rather than a mistake — so this states the exposure and declines to
 * recommend a purchase.
 */
export function checkNoEdge(posture: OriginPosture): OriginFinding[] {
  const routableWeb = posture.webIps.filter((ip) => !isNonRoutable(ip));
  if (routableWeb.length === 0) return [];

  // Could not fetch the app: we do not know, and unknown is never a finding.
  // Without this the check reported "no edge protection" for every app that was
  // simply unreachable at scan time.
  if (!posture.headers) return [];

  if (detectEdge(posture)) return [];

  return [
    {
      id: "origin:no_edge_protection",
      severity: "INFO",
      title: "Your app is served directly, not from behind an edge network",
      consequence:
        `${posture.domain} resolves to ${routableWeb.join(", ")}, which we do not recognise as a CDN or edge network. That usually means requests reach your server directly. ` +
        `This is a note, not a fault — serving directly is a normal choice, and for a small app it is often the right one. It is here because it decides who absorbs a traffic spike: with nothing in front, your server does, and the first sign is usually the site being down. ` +
        `We handle the application-layer side of this — credential stuffing, scrapers, floods aimed at expensive endpoints — but a volumetric attack is absorbed by network capacity, which is not something we can do from inside your app. If you ever need that, it comes from a provider in front of you. ` +
        `If you are already behind something we did not recognise, ignore this.`,
    },
  ];
}

/** Both origin checks. */
export function analyzeOriginPosture(posture: OriginPosture): OriginFinding[] {
  return [...checkOriginLeak(posture), ...checkNoEdge(posture)];
}

/**
 * Gathers the DNS facts. Every lookup is independent and failure-tolerant: a
 * domain with no MX records is ordinary, and an unresolvable name yields nothing
 * rather than a finding.
 */
export async function collectOriginPosture(
  domain: string,
  dns: DnsResolver,
  headers?: Record<string, string>,
  unread: string[] = [],
): Promise<OriginPosture | null> {
  // Absence (ENODATA/ENOTFOUND) is a real answer; any other failure means the
  // origin findings from this pass cannot be trusted to have cleared.
  const safe = async <T>(p: Promise<T[]>): Promise<T[]> => p.catch((err) => {
    if (!isAbsenceError(err) && !unread.includes("origin:")) unread.push("origin:");
    return [];
  });

  const [webIps, cnames, mx] = await Promise.all([
    safe(dns.resolve4(domain)),
    safe(dns.resolveCname(domain)),
    safe(dns.resolveMx(domain)),
  ]);

  if (webIps.length === 0 && cnames.length === 0) return null;

  const mxHosts = mx.map((m) => m.exchange).filter(Boolean);
  const mxIpLists = await Promise.all(mxHosts.map((h) => safe(dns.resolve4(h))));

  return {
    domain,
    webIps,
    cnames,
    mxHosts,
    mxIps: [...new Set(mxIpLists.flat())],
    headers,
  };
}

/** Node-backed resolver. */
export const nodeDnsResolver: DnsResolver = {
  async resolve4(name) {
    const { resolve4 } = await import("node:dns/promises");
    return resolve4(name);
  },
  async resolveMx(name) {
    const { resolveMx } = await import("node:dns/promises");
    return resolveMx(name);
  },
  async resolveCname(name) {
    const { resolveCname } = await import("node:dns/promises");
    return resolveCname(name);
  },
};

/** Fetches the response headers an edge provider would announce itself in. */
export async function fetchOriginHeaders(
  appUrl: string, signal?: AbortSignal,
): Promise<Record<string, string> | undefined> {
  try {
    const res = await guardedFetch(appUrl, {
      method: "HEAD",
      signal: requestSignal(signal, 8_000),
    });
    const out: Record<string, string> = {};
    res.headers.forEach((value, key) => {
      out[key.toLowerCase()] = value;
    });
    return out;
  } catch {
    // Undefined, not empty: "we could not look" must stay distinct from
    // "we looked and found no edge".
    return undefined;
  }
}
