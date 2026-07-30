import { parseAllowList, splitEntry, isLocalEntry } from "./authConfigScan";
import type { SupabaseAuthConfig } from "./supabaseMgmt";

// Unit 5 from CHECK-SPEC.md §5 — work out the customer's live app URL instead of
// asking for it.
//
// The friction budget is two connections, GitHub and Supabase, and nothing else.
// Every field on the onboarding form is a place someone stalls, and this
// particular field is worse than most: it's optional, so people skip it, and
// skipping it silently disables an entire surface of checks (exposed paths,
// source maps, secrets in the shipped bundle, email authentication). The result
// is a customer who believes they're fully monitored while a third of the
// product isn't running.
//
// We don't need to ask. Once Supabase is connected, the project's own auth
// configuration already contains the answer, because Supabase needs the same URL
// to send password-reset emails:
//
//   1. site_url — the canonical production URL. Correct when it's been set.
//   2. the redirect allow-list — the fallback that matters in practice, because
//      site_url is very commonly left at http://localhost:3000 (we flag that
//      separately) while the real URL sits in the allow-list for OAuth to work.
//
// Deriving from (2) when (1) is unusable is what makes this reliable rather than
// theoretical: a project with a default site_url is exactly the kind of project
// whose owner also skipped the optional field.

/**
 * A candidate must be a real, fetchable, public origin. Rejecting the rest
 * matters because whatever comes back here gets fetched by the app-surface
 * checks — a bad value would produce confusing findings against the wrong host,
 * or none at all.
 */
export function normaliseCandidate(raw: string): string | null {
  const trimmed = raw.trim();
  if (!trimmed) return null;

  const { scheme, host } = splitEntry(trimmed);
  if (scheme !== "http" && scheme !== "https") return null; // incl. mobile schemes
  if (!host) return null;

  // A wildcard in the HOST makes this a pattern, not an address —
  // `https://*.example.com` is not somewhere we can fetch. A wildcard in the
  // PATH is fine and extremely common (`https://app.example.com/**` is the form
  // Supabase recommends), and it doesn't survive the reduction to origin below.
  // Rejecting on the whole string would have discarded almost every usable
  // allow-list entry.
  if (/[*?[\]{}]/.test(host)) return null;

  if (isLocalEntry(host)) return null;
  // Needs a dot to be a public hostname; also rejects bare `http://intranet`.
  if (!host.includes(".")) return null;

  try {
    // Rebuilt from scheme+host so a path wildcard can't reach URL(), which would
    // reject or mangle it.
    const url = new URL(`${scheme}://${host}`);
    // Origin only. The app-surface checks probe paths from the root, and a
    // stored `/auth/callback` would make every probe resolve against the wrong
    // base.
    return url.origin;
  } catch {
    return null;
  }
}

/**
 * Best app URL derivable from the auth config, or null.
 *
 * Prefers site_url, then the first usable allow-list entry. https wins over http
 * regardless of position, since a customer with both listed is reachable on
 * https and that's what we should be auditing.
 */
export function deriveAppUrl(config: SupabaseAuthConfig | null): string | null {
  if (!config) return null;

  const siteUrl = typeof config.site_url === "string" ? normaliseCandidate(config.site_url) : null;
  if (siteUrl?.startsWith("https://")) return siteUrl;

  const fromAllowList = parseAllowList(
    typeof config.uri_allow_list === "string" ? config.uri_allow_list : null
  )
    .map(normaliseCandidate)
    .filter((entry): entry is string => entry !== null);

  // Deduplicate so "first https" is stable when the same origin appears with
  // several paths.
  const unique = [...new Set(fromAllowList)];

  return unique.find((entry) => entry.startsWith("https://")) ?? siteUrl ?? unique[0] ?? null;
}
