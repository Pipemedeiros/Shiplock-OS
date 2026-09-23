// SSRF guard for every server-side fetch driven by a customer-submitted URL.
//
// appUrl (validated only for shape in lib/sanitize.ts: https:// + well-formed)
// flows straight into fetch() in bundleAudit.ts and exposedPaths.ts, and is
// PERSISTED as monitored_app_url and re-fetched automatically on every 48h
// monitoring pass (lib/monitoring/run.ts) — so this isn't a one-time request
// a human could review, it's a standing "fetch whatever a paid customer once
// typed" primitive running unattended, on a cron, indefinitely. A customer
// (or anyone who briefly controlled a customer's account) could point it at
// cloud metadata (169.254.169.254), localhost, or an RFC1918 address reachable
// from the function's network. Found via secmax's SSRF checklist item.
//
// Injectable resolver, same pattern as originExposure.ts's DnsResolver — real
// DNS in production, a fake in tests so this never depends on network access.
export interface HostResolver {
  lookup(hostname: string): Promise<string[]>;
}

export const nodeHostResolver: HostResolver = {
  async lookup(hostname) {
    const { lookup } = await import("node:dns/promises");
    const results = await lookup(hostname, { all: true, verbatim: true });
    return results.map((r) => r.address);
  },
};

export class SsrfBlockedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SsrfBlockedError";
  }
}

/** IPv4 octets, each 0-255, from a literal dotted-quad string. */
function ipv4Octets(ip: string): number[] | null {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  const nums = parts.map(Number);
  if (nums.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return null;
  return nums;
}

/**
 * True for any address a fetch must never reach: loopback, link-local
 * (including the AWS/GCP/Azure cloud metadata address), RFC1918 private
 * ranges, CGNAT, "this network", benchmarking/documentation ranges,
 * multicast/reserved space, and the IPv6 equivalents. Pure and unit-tested
 * directly — this is the part that must never regress silently.
 */
export function isPrivateOrReservedIp(ip: string): boolean {
  const v4 = ipv4Octets(ip);
  if (v4) {
    const [a, b] = v4;
    if (a === 127) return true; // loopback
    if (a === 10) return true; // RFC1918
    if (a === 172 && b >= 16 && b <= 31) return true; // RFC1918
    if (a === 192 && b === 168) return true; // RFC1918
    if (a === 169 && b === 254) return true; // link-local incl. cloud metadata
    if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT (RFC6598)
    if (a === 0) return true; // "this network"
    if (a === 192 && b === 0 && v4[2] === 0) return true; // IETF protocol assignments
    if (a === 192 && b === 0 && v4[2] === 2) return true; // TEST-NET-1
    if (a === 198 && (b === 18 || b === 19)) return true; // benchmarking
    if (a === 198 && b === 51 && v4[2] === 100) return true; // TEST-NET-2
    if (a === 203 && b === 0 && v4[2] === 113) return true; // TEST-NET-3
    if (a >= 224) return true; // multicast (224-239) + reserved (240-255)
    return false;
  }

  // IPv6 — normalize what we need without a full parser.
  const lower = ip.toLowerCase();
  if (lower === "::1" || lower === "::") return true; // loopback / unspecified
  if (lower.startsWith("fe80:") || lower.startsWith("fe8") || lower.startsWith("fe9") ||
      lower.startsWith("fea") || lower.startsWith("feb")) return true; // link-local fe80::/10
  if (lower.startsWith("fc") || lower.startsWith("fd")) return true; // unique local fc00::/7
  // IPv4-mapped/compatible IPv6 (::ffff:a.b.c.d) — recheck the embedded v4.
  const mapped = lower.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (mapped) return isPrivateOrReservedIp(mapped[1]);
  return false;
}

/**
 * Resolves `url`'s hostname and throws SsrfBlockedError if the protocol isn't
 * https, or if ANY resolved address is private/loopback/link-local/reserved.
 * Call this before every fetch driven by a customer-submitted URL — including
 * every redirect hop, since a public host can 30x to an internal one.
 */
export async function assertPublicHttpsUrl(
  url: string,
  resolver: HostResolver = nodeHostResolver
): Promise<void> {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new SsrfBlockedError(`Not a valid URL: ${url}`);
  }
  if (parsed.protocol !== "https:") {
    throw new SsrfBlockedError(`Refusing non-https URL: ${url}`);
  }

  let addresses: string[];
  try {
    addresses = await resolver.lookup(parsed.hostname);
  } catch {
    throw new SsrfBlockedError(`Could not resolve host: ${parsed.hostname}`);
  }
  if (addresses.length === 0 || addresses.some(isPrivateOrReservedIp)) {
    throw new SsrfBlockedError(`Host resolves to a non-public address: ${parsed.hostname}`);
  }
}

/**
 * fetch() that validates the target AND every redirect hop before following
 * it — plain `redirect: "follow"` performs the internal request before we
 * ever see where it landed, which defeats a same-origin-looking initial URL
 * check. Bounded to a handful of hops; anything longer is treated as a
 * failure the same way a network error is (best-effort callers already
 * expect and handle that).
 */
export async function guardedFetch(
  url: string,
  init: RequestInit = {},
  opts: { resolver?: HostResolver; maxRedirects?: number } = {}
): Promise<Response> {
  const resolver = opts.resolver ?? nodeHostResolver;
  const maxRedirects = opts.maxRedirects ?? 3;

  let target = url;
  for (let hop = 0; hop <= maxRedirects; hop++) {
    // Every hop is still validated; cancellation only stops the chain early.
    init.signal?.throwIfAborted();
    await assertPublicHttpsUrl(target, resolver);
    init.signal?.throwIfAborted();
    const res = await fetch(target, { ...init, redirect: "manual" });
    const isRedirect = res.status >= 300 && res.status < 400;
    const location = res.headers.get("location");
    if (!isRedirect || !location) return res;
    target = new URL(location, target).href;
  }
  throw new SsrfBlockedError(`Too many redirects fetching ${url}`);
}
