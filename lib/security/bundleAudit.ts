import type { Severity } from "@/lib/types";
import { jwtRole } from "@/lib/deep/clientExposure";
import { guardedFetch } from "@/lib/security/ssrfGuard";
import { requestSignal } from "@/lib/abort";
import { API_PATH, calledPaths, requestedPaths, type ShippedRead } from "./shippedCalls";

// Audit what the customer's app ACTUALLY ships
// to a browser, fetched from the public internet the way a visitor gets it.
//
// Why this exists alongside the source checks, which look for the same class of mistake in
// source: those two need GitHub connected, and they reason about what SHOULD end
// up in the bundle. This one reads the bundle itself. It therefore catches the
// cases source analysis structurally cannot:
//   - a key injected at build time by the host's env config, in no repo file
//   - a key in a repo we didn't read (private, unconnected, or past the cap)
//   - a bundler inlining something no one asked it to
//   - a stale deploy still serving a key that was already removed from source
//
// It is also the only check in the product that proves the leak rather than
// inferring it. "Your source imports the admin client from a client component"
// is an argument. "Here is your service-role key, in this file, that we
// downloaded anonymously" is not arguable — and it's the same thing an attacker
// would have found.
//
// PRECISION: static hosts answer 200 with index.html for anything, so nothing
// here trusts a status code alone. Every finding needs a content signature, and
// the anon/publishable key — which is SUPPOSED to be in the bundle — is
// explicitly not a finding.

interface BundleFinding {
  id: string;
  severity: Severity;
  title: string;
  consequence: string;
}

// ── Pure: what the page loads ──────────────────────────────────────────────

const SCRIPT_SRC_RE = /<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["']/gi;
const OWN_BUILD = /\/_next\/static\//;

/**
 * The page's own script URLs from its HTML, absolute and deduped.
 *
 * Same-origin, plus the app's own Next.js build on an asset host (assetPrefix
 * puts it under /_next/static/ on a CDN). Third-party scripts (analytics,
 * Stripe, intercom) are not the customer's build output — auditing them would
 * mean reporting other companies' code as this customer's finding, and
 * fetching unrelated hosts on their behalf.
 */
export function extractScriptUrls(html: string, pageUrl: string): string[] {
  let origin: string;
  try {
    origin = new URL(pageUrl).origin;
  } catch {
    return [];
  }

  const urls: string[] = [];
  const seen = new Set<string>();
  SCRIPT_SRC_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = SCRIPT_SRC_RE.exec(html)) !== null) {
    let abs: URL;
    try {
      abs = new URL(m[1], pageUrl);
    } catch {
      continue;
    }
    if (abs.origin !== origin && !OWN_BUILD.test(abs.pathname)) continue;
    if (!/^https?:$/.test(abs.protocol)) continue;
    const href = abs.href;
    if (seen.has(href)) continue;
    seen.add(href);
    urls.push(href);
  }
  return urls;
}

/** The `sourceMappingURL` a bundle points at, resolved absolute. */
export function findSourceMapUrl(js: string, jsUrl: string): string | null {
  // Last one wins, matching how browsers read it.
  const matches = [...js.matchAll(/[#@]\s*sourceMappingURL\s*=\s*(\S+)/g)];
  const ref = matches.at(-1)?.[1];
  if (!ref) return null;
  if (ref.startsWith("data:")) return null; // inlined, not a separate fetch
  try {
    return new URL(ref, jsUrl).href;
  } catch {
    return null;
  }
}

/**
 * Judges a fetched source map. Only a map we can actually parse counts — a
 * `sourceMappingURL` comment whose target 404s is the normal, correct state
 * (the comment survives minification; the map was never deployed), and
 * reporting it would be a false positive on a properly configured app.
 */
export function classifySourceMap(status: number, body: string, jsUrl: string): BundleFinding | null {
  if (status !== 200) return null;

  let map: { sources?: unknown; sourcesContent?: unknown };
  try {
    map = JSON.parse(body) as typeof map;
  } catch {
    return null; // not a source map (catch-all HTML, error page, truncated)
  }
  if (!Array.isArray(map.sources)) return null;

  const hasContent = Array.isArray(map.sourcesContent) && map.sourcesContent.some((s) => typeof s === "string" && s.length > 0);
  const name = jsUrl.split("/").pop() ?? jsUrl;

  return {
    id: `bundle:source_map_exposed:${hasContent ? "with_content" : "paths_only"}`,
    severity: hasContent ? "WARNING" : "INFO",
    title: hasContent
      ? "Your original source code is downloadable from your live site"
      : "Source maps are served in production (file paths only)",
    consequence: hasContent
      ? `The source map for ${name} is publicly downloadable and contains your original, unminified source. Anyone can reconstruct your codebase, including comments, internal API routes, feature flags, and any logic you assumed was hidden by minification. Minification was never security, but shipping the map removes even the small friction it provided. Turn off production source maps (in Next.js, leave productionBrowserSourceMaps off), or restrict .map files at your host so only your error reporter can fetch them.`
      : `The source map for ${name} is publicly downloadable. It doesn't include your source text, but it does reveal your project's internal file and directory structure, which tells an attacker how your app is organised and what to look for. Turn off production source maps or restrict .map files at your host.`,
  };
}

// ── Pure: secrets in what was shipped ──────────────────────────────────────

/**
 * Credential shapes that must never appear in a browser bundle. Every entry is
 * a distinctive, vendor-issued prefix — not a heuristic — because a false
 * positive here means telling a founder to rotate a key that was fine.
 *
 * The anon / publishable keys are deliberately absent: they belong in the
 * bundle. That's what they're for.
 */
const BUNDLE_SECRETS: { id: string; label: string; re: RegExp; rotate: string }[] = [
  {
    id: "supabase_secret_key",
    label: "a Supabase secret key (sb_secret_…)",
    re: /\bsb_secret_[A-Za-z0-9_-]{10,}/,
    rotate: "Rotate it in Supabase → Project Settings → API Keys immediately, then find the client-side code reading it.",
  },
  {
    id: "stripe_live_secret",
    label: "a live Stripe secret key (sk_live_…)",
    re: /\bsk_live_[A-Za-z0-9]{16,}/,
    rotate: "Roll it in the Stripe dashboard now; a live secret key can move real money and read every customer record.",
  },
  {
    id: "stripe_test_secret",
    label: "a Stripe test secret key (sk_test_…)",
    re: /\bsk_test_[A-Za-z0-9]{16,}/,
    rotate: "Roll it in Stripe. No real money is at risk, but the same code path will ship your live key the moment you switch modes.",
  },
  {
    id: "anthropic_key",
    label: "an Anthropic API key (sk-ant-…)",
    re: /\bsk-ant-[A-Za-z0-9_-]{20,}/,
    rotate: "Revoke it in the Anthropic console. A leaked API key gets used, and you get the bill.",
  },
  {
    id: "openai_key",
    label: "an OpenAI API key",
    re: /\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}/,
    rotate: "Revoke it in the OpenAI dashboard. A leaked API key gets used, and you get the bill.",
  },
  {
    id: "aws_access_key",
    label: "an AWS access key id (AKIA…)",
    re: /\bAKIA[0-9A-Z]{16}\b/,
    rotate: "Disable the key in IAM immediately and review CloudTrail for use you don't recognise.",
  },
  {
    id: "google_api_key",
    label: "a Google API key (AIza…)",
    re: /\bAIza[0-9A-Za-z_-]{35}\b/,
    rotate: "Restrict it to your domain in the Google Cloud console (HTTP referrer restrictions), or rotate it. Some Google keys are safe to ship IF restricted; an unrestricted one is billable by anyone.",
  },
  {
    id: "private_key",
    label: "a PEM private key",
    re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/,
    rotate: "Rotate the key pair immediately. A private key in a public bundle is fully compromised.",
  },
  {
    id: "github_token",
    label: "a GitHub token (ghp_/ghs_…)",
    re: /\bgh[pso]_[A-Za-z0-9]{20,}/,
    rotate: "Revoke it in GitHub → Settings → Developer settings immediately; it can read (and possibly write) your repositories.",
  },
];

/**
 * Secrets in the shipped JavaScript.
 *
 * Two passes: known credential prefixes, and any Supabase JWT whose decoded
 * role isn't `anon`. The second is the one that matters most and the one no
 * regex-only scanner catches, because the service-role key and the anon key are
 * character-for-character indistinguishable until you decode the payload — and
 * the anon key is supposed to be right there in the same bundle.
 */
export function scanBundleSecrets(js: string, jsUrl: string): BundleFinding[] {
  const out: BundleFinding[] = [];
  const name = jsUrl.split("/").pop()?.split("?")[0] ?? jsUrl;

  for (const secret of BUNDLE_SECRETS) {
    if (!secret.re.test(js)) continue;
    out.push({
      id: `bundle:shipped_secret:${secret.id}`,
      severity: "CRITICAL",
      title: `${secret.label} is in your public JavaScript`,
      consequence: `We downloaded ${name} from your live site (no login, no special access, the same file every visitor gets) and found ${secret.label} inside it. Treat this key as public: assume it is already copied, and that removing it from your code does not un-leak it. ${secret.rotate}`,
    });
  }

  // Any Supabase-style JWT in the bundle, checked by decoded role.
  for (const m of js.matchAll(/\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g)) {
    const role = jwtRole(m[0]);
    if (!role || role === "anon") continue; // anon belongs here
    out.push({
      id: `bundle:shipped_secret:supabase_${role}_jwt`,
      severity: "CRITICAL",
      title: `Your Supabase "${role}" key is in your public JavaScript`,
      consequence: `${name} is served publicly from your site, and it contains a Supabase key whose decoded role is "${role}". A service-role key ignores Row Level Security completely: whoever holds it can read, change, or delete every row in every table, regardless of what your policies say. Anyone who has viewed your site's source has it. Rotate it in Supabase → Project Settings → API Keys right now (that is the only action that stops this) and then replace the client-side usage with the anon key. This usually happens because the anon and service-role keys sit next to each other in the dashboard and look identical.`,
    });
    break; // one finding per bundle; the fix is the same rotation
  }

  return out;
}

// ── Pure: the pages a visitor reaches next ─────────────────────────────────

// A link whose GET may change something, or that names a backend address
// rather than a page, is never followed: this pass reads what a visitor's
// click would show and nothing a click would do.
const NOT_A_PAGE = /(?:log|sign)[-_]?out|delete|remove|unsubscribe|callback|confirm|verify|reset|invite|accept|download|export/i;

/** Same-origin pages the home page links to, absolute, sorted, excluding itself. */
function linkedPages(html: string, pageUrl: string): string[] {
  let home: URL;
  try { home = new URL(pageUrl); } catch { return []; }
  const out = new Set<string>();
  for (const path of requestedPaths(html)) {
    if (API_PATH.test(path) || NOT_A_PAGE.test(path) || path.includes("[")) continue;
    const url = new URL(path, home);
    if (url.origin !== home.origin || url.pathname === home.pathname) continue;
    out.add(url.href);
  }
  return [...out].sort();
}

// ── Network orchestration ──────────────────────────────────────────────────

const TIMEOUT_MS = 8_000;
const PAGE_TIMEOUT_MS = 5_000;
const MAX_PAGES = 8;
const MAX_SCRIPTS = 48;
// Scripts in flight at once: a pass reads like a visitor, not a burst.
const CONCURRENCY = 8;
const MAX_JS_BYTES = 2_000_000; // a big Next.js chunk; beyond this we read a prefix
const MAX_MAP_BYTES = 4_000_000;

/**
 * Reads at most `limit` bytes of a response, then abandons the rest. Bundles can
 * be tens of megabytes; a monitoring pass must not be able to exhaust memory on
 * whatever a customer happens to serve.
 */
export async function readCapped(res: Response, limit: number): Promise<string> {
  if (!res.body) return (await res.text().catch(() => "")).slice(0, limit);
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let out = "";
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      out += decoder.decode(value, { stream: true });
      if (out.length >= limit) break;
    }
  } catch {
    /* truncated read — scan what we got */
  } finally {
    await reader.cancel().catch(() => {});
  }
  return out.slice(0, limit);
}

/**
 * The bundle audit against a live app URL: its page, the same-origin pages it links to,
 * and the scripts they load.
 *
 * Best-effort throughout: any network failure means "we could not prove a
 * problem", never a finding. A monitoring pass reporting a vulnerability because
 * a fetch timed out would be worse than reporting nothing.
 */
export async function auditShippedBundle(
  appUrl: string, signal?: AbortSignal, unread: string[] = [], shipped?: ShippedRead,
): Promise<BundleFinding[]> {
  // Failed reads never produce findings, and they record which finding families
  // this pass could not verify so the caller cannot mistake them for fixed.
  const chunksUnread = () => unread.push("bundle:shipped_secret:", "bundle:source_map_exposed:");
  const found = new Map<string, BundleFinding>();
  const add = (finding: BundleFinding) => {
    if (!found.has(finding.id)) found.set(finding.id, finding);
  };
  // The paths this JavaScript names, and those it requests itself.
  const keep = (text: string) => {
    if (!shipped) return;
    for (const p of calledPaths(text)) shipped.paths.add(p);
    for (const p of requestedPaths(text)) shipped.requests.add(p);
  };

  let html: string;
  let pageUrl: string;
  try {
    const res = await guardedFetch(appUrl, { signal: requestSignal(signal, TIMEOUT_MS) });
    if (!res.ok) {
      unread.push("bundle:");
      return [];
    }
    pageUrl = res.url || appUrl;
    html = await readCapped(res, 1_000_000);
  } catch {
    unread.push("bundle:");
    return [];
  }
  if (shipped) { shipped.pageRead = true; shipped.pagesRead = 1; }
  keep(html);
  // An inline-only page (or one whose entry chunk we can't see) still gets its
  // HTML checked — bundlers and hand-written templates both inline keys there.
  for (const finding of scanBundleSecrets(html, pageUrl)) add(finding);

  // A home page loads only its own chunks; the pages it links to load theirs.
  // An error answer is what a visitor gets (nothing to read); a failed read
  // leaves that page's scripts unread.
  const origin = new URL(pageUrl).origin;
  const pages = linkedPages(html, pageUrl);
  if (pages.length > MAX_PAGES) chunksUnread();
  const linked = await Promise.all(pages.slice(0, MAX_PAGES).map(async (url) => {
    try {
      const res = await guardedFetch(url, { signal: requestSignal(signal, PAGE_TIMEOUT_MS) });
      if (res.status >= 500) { chunksUnread(); return null; }
      const at = res.url || url;
      if (new URL(at).origin !== origin) return null;
      if (shipped) shipped.pagesRead++;
      if (!res.ok) return null;
      const body = await readCapped(res, 1_000_000);
      keep(body);
      for (const finding of scanBundleSecrets(body, at)) add(finding);
      return { html: body, url: at };
    } catch {
      chunksUnread();
      return null;
    }
  }));

  const allScripts = [...new Set([{ html, url: pageUrl }, ...linked.filter((p) => p !== null)]
    .flatMap((p) => extractScriptUrls(p.html, p.url)))];
  if (allScripts.length > MAX_SCRIPTS) chunksUnread();
  const scripts = allScripts.slice(0, MAX_SCRIPTS);
  if (shipped) shipped.scriptsSeen = allScripts.length;

  await forEachLimited(
    scripts, CONCURRENCY, async (jsUrl) => {
      let js: string;
      try {
        const res = await guardedFetch(jsUrl, { signal: requestSignal(signal, TIMEOUT_MS) });
        if (!res.ok) {
          chunksUnread();
          return;
        }
        js = await readCapped(res, MAX_JS_BYTES);
      } catch {
        chunksUnread();
        return;
      }
      if (shipped) shipped.scriptsRead++;
      keep(js);

      for (const finding of scanBundleSecrets(js, jsUrl)) add(finding);

      const mapUrl = findSourceMapUrl(js, jsUrl);
      if (!mapUrl) return;
      try {
        const res = await guardedFetch(mapUrl, { signal: requestSignal(signal, TIMEOUT_MS) });
        if (res.status >= 500) unread.push("bundle:source_map_exposed:");
        const body = await readCapped(res, MAX_MAP_BYTES);
        const finding = classifySourceMap(res.status, body, jsUrl);
        if (finding) add(finding);
      } catch {
        unread.push("bundle:source_map_exposed:");
      }
    });

  return [...found.values()];
}

/** Runs work over items with at most `limit` in flight. */
async function forEachLimited<T>(items: readonly T[], limit: number, work: (item: T) => Promise<void>): Promise<void> {
  let next = 0;
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (next < items.length) await work(items[next++]);
  }));
}

// Exposed for tests.
export const _BUNDLE_SECRETS = BUNDLE_SECRETS;
