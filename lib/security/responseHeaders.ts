import type { Severity } from "@/lib/types";
import { guardedFetch } from "@/lib/security/ssrfGuard";
import { requestSignal } from "@/lib/abort";

/**
 * Two hardening headers on the founder's live home page, read the way a
 * visitor's browser gets them (the outside view): whether another site may
 * frame the app (clickjacking) and whether browsers are told to always use
 * HTTPS. Only a 200 HTML answer is judged; anything else leaves the family
 * unread, never clean. INFO: a missing header is a gap to close, not a
 * confirmed exposure, so it never moves the status.
 */
export interface HeaderFinding { id: string; severity: Severity; title: string; consequence: string }

const TIMEOUT_MS = 8_000;

function framesRefused(h: Record<string, string>): boolean {
  if (/^\s*(deny|sameorigin)\s*$/i.test(h["x-frame-options"] ?? "")) return true;
  // Only the enforced policy counts; report-only refuses nothing.
  const rule = /(?:^|;)\s*frame-ancestors\s+([^;]*)/i.exec(h["content-security-policy"] ?? "")?.[1]?.trim();
  return Boolean(rule) && !rule!.split(/\s+/).includes("*");
}

function httpsPinned(h: Record<string, string>): boolean {
  const age = /max-age\s*=\s*"?(\d+)/i.exec(h["strict-transport-security"] ?? "")?.[1];
  return age !== undefined && Number(age) > 0;
}

export function judgeHeaders(headers: Record<string, string>, https: boolean): HeaderFinding[] {
  const out: HeaderFinding[] = [];
  if (!framesRefused(headers)) out.push({
    id: "headers:frame_protection_missing", severity: "INFO",
    title: "Any site can show your app inside a frame",
    consequence: "Your home page answered without X-Frame-Options or a Content-Security-Policy frame-ancestors rule, so another site can load your app in an invisible frame and lead a signed-in user to click buttons they cannot see (clickjacking). Send X-Frame-Options: DENY, or Content-Security-Policy: frame-ancestors 'none' (or 'self' if you frame your own pages). In Next.js, set it in the headers() of next.config.",
  });
  if (https && !httpsPinned(headers)) out.push({
    id: "headers:hsts_missing", severity: "INFO",
    title: "Browsers are not told to always use HTTPS",
    consequence: "Your home page answered without a Strict-Transport-Security header, so a browser that reaches your address over plain http first can be sent an insecure page on a hostile network before your redirect runs. Send Strict-Transport-Security: max-age=63072000; includeSubDomains once every subdomain serves HTTPS.",
  });
  return out;
}

export async function auditResponseHeaders(appUrl: string, signal?: AbortSignal, unread: string[] = []): Promise<HeaderFinding[]> {
  try {
    const res = await guardedFetch(appUrl, { signal: requestSignal(signal, TIMEOUT_MS) });
    await res.body?.cancel().catch(() => {});
    if (res.status !== 200 || !/text\/html/i.test(res.headers.get("content-type") ?? "")) {
      unread.push("headers:");
      return [];
    }
    const headers: Record<string, string> = {};
    res.headers.forEach((value, key) => { headers[key.toLowerCase()] = value; });
    return judgeHeaders(headers, (res.url || appUrl).startsWith("https:"));
  } catch {
    unread.push("headers:");
    return [];
  }
}
