import { requestSignal } from "@/lib/abort";
import { isSharedHost } from "./emailAuth";
import { readCapped } from "./bundleAudit";

/**
 * Other names on the founder's own domain, from certificate transparency
 * logs: the public record every certificate authority must publish. A name
 * there is an address someone once secured under the domain, often one the
 * team forgot (a staging copy, an old admin panel, a preview). ShipLock only
 * lists them for the founder to review; it sends nothing to those addresses,
 * and only the address the founder confirmed is read (AGENTS.md: no
 * third-party targets). Read from Cert Spotter's public API (crt.sh answered
 * 502 on every try, 2026-10-17); a failed read is "not read", never "no
 * other names". Unauthenticated, so rate limited: one read per 48 hour pass.
 */
export const MAX_NAMES = 50;
const TIMEOUT_MS = 10_000;
const MAX_BYTES = 5_000_000;
// Common two-part public suffixes; anything else is read as one label. Not
// the full public suffix list: a miss widens or narrows the search, it never
// reads another domain's addresses.
const TWO_PART = /\.(com|net|org|gov|edu|co|ac|or|ne)\.(br|uk|au|nz|jp|kr|in|za|mx|ar|tr|il|id|th|sg|my)$/;
const NAME = /^[a-z0-9-]+(\.[a-z0-9-]+)+$/;

export type CertificateName = { name: string; lastIssued: string };

export function registrableDomain(host: string): string | null {
  const h = host.toLowerCase().replace(/\.$/, "");
  if (!h.includes(".") || /^[\d.]+$/.test(h) || !NAME.test(h)) return null;
  const labels = h.split(".");
  const keep = TWO_PART.test(h) ? 3 : 2;
  return labels.length < keep ? null : labels.slice(-keep).join(".");
}

/** Each other name under `apex`, newest issue first, or null for a malformed log. */
export function otherCertificateNames(log: unknown, apex: string, confirmedHost: string): CertificateName[] | null {
  if (!Array.isArray(log)) return null;
  const newest = new Map<string, string>();
  for (const entry of log as { dns_names?: unknown; not_before?: unknown }[]) {
    if (!Array.isArray(entry?.dns_names) || typeof entry.not_before !== "string") continue;
    const day = entry.not_before.slice(0, 10);
    for (const raw of entry.dns_names) {
      if (typeof raw !== "string") continue;
      const name = raw.trim().toLowerCase().replace(/^\*\./, "");
      if (!NAME.test(name) || name === confirmedHost.toLowerCase()) continue;
      if (name !== apex && !name.endsWith(`.${apex}`)) continue;
      if ((newest.get(name) ?? "") < day) newest.set(name, day);
    }
  }
  return [...newest].map(([name, lastIssued]) => ({ name, lastIssued }))
    .sort((a, b) => b.lastIssued.localeCompare(a.lastIssued) || a.name.localeCompare(b.name)).slice(0, MAX_NAMES);
}

/** The other names for the app's domain; null when the log could not be read;
 * undefined when it does not apply (a platform's shared domain, such as
 * vercel.app, is not the founder's to review). */
export async function readCertificateNames(appUrl: string, signal?: AbortSignal): Promise<CertificateName[] | null | undefined> {
  let host: string;
  try { host = new URL(appUrl).hostname.toLowerCase(); } catch { return undefined; }
  if (isSharedHost(host)) return undefined;
  const apex = registrableDomain(host);
  if (!apex) return undefined;
  try {
    const res = await fetch(`https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(apex)}&include_subdomains=true&expand=dns_names`,
      { signal: requestSignal(signal, TIMEOUT_MS), headers: { Accept: "application/json" } });
    if (!res.ok) return null;
    // Stops reading at the cap; a cut log fails to parse and reads as not read.
    return otherCertificateNames(JSON.parse(await readCapped(res, MAX_BYTES)), apex, host);
  } catch {
    return null;
  }
}
