import type { GithubFinding } from "./githubScan";
import type { SupabaseAuthConfig } from "./supabaseMgmt";

// The redirect allow-list on Supabase Auth.
//
// This list is the only thing standing between a login flow and token theft.
// After a successful sign-in, Supabase sends the user to a URL carrying their
// session, and it will send them to ANY url the allow-list permits. Widen the
// list to somewhere an attacker controls and the attack is a single link:
//
//   1. attacker sends the victim a normal-looking login link for the real app,
//      with redirectTo pointing at a host the allow-list happens to permit
//   2. the victim logs in — genuinely, on the real domain, with the real form,
//      and any 2FA they have
//   3. Supabase redirects to the attacker's URL with the session attached
//
// Nothing about that looks like phishing to the victim; the credentials never
// leave the legitimate site. The tokens simply arrive somewhere else. This is
// why a wildcard here is a full account takeover primitive and not a
// configuration nit.
//
// Wildcard semantics, from Supabase's own docs (verified, not assumed):
//   *  matches any run of NON-SEPARATOR characters
//   ** matches any characters AT ALL, including separators
//   separators are `.` and `/`
// The consequence that matters: `*` stays inside one label, but `**` crosses
// dots and slashes, so a `**` anywhere in the host authorises arbitrary hosts.
// Supabase's own recommendation is an exact URL in production.

const f = (
  id: string,
  severity: GithubFinding["severity"],
  title: string,
  consequence: string
): GithubFinding => ({
  id,
  severity,
  title,
  consequence,
  packageName: null,
  version: null,
  vulnId: null,
  cveId: null,
});

// Field names are read tolerantly, and that is a deliberate response to a bug we
// already shipped once: lib/deep/policyScan.ts had an allow-list of advisor lint
// names containing two that don't exist, so those findings were silently dropped
// for months. The failure mode is the dangerous one — a key we don't recognise
// looks exactly like a clean project.
//
// So: accept the documented snake_case plus the plausible variants, and if the
// config comes back populated with NONE of the keys we know, say so loudly
// instead of returning "no findings".
const ALLOW_LIST_KEYS = ["uri_allow_list", "uriAllowList", "URI_ALLOW_LIST", "additional_redirect_urls"];
const SITE_URL_KEYS = ["site_url", "siteUrl", "SITE_URL"];

function readString(config: SupabaseAuthConfig, keys: string[]): string | null {
  for (const key of keys) {
    const value = config[key];
    if (typeof value === "string") return value;
  }
  return null;
}

/**
 * True when the config object has content but none of the keys we understand —
 * i.e. our field-name assumption is wrong and every check here would silently
 * pass. Surfaced rather than swallowed.
 */
export function isUnrecognisedConfigShape(config: SupabaseAuthConfig): boolean {
  if (Object.keys(config).length === 0) return false;
  return readString(config, ALLOW_LIST_KEYS) === null && readString(config, SITE_URL_KEYS) === null;
}

/** Splits the stored allow-list. Supabase stores it comma-separated. */
export function parseAllowList(raw: string | null | undefined): string[] {
  if (!raw) return [];
  return raw
    .split(",")
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);
}

interface EntryParts {
  scheme: string | null;
  host: string;
  path: string;
}

/**
 * Splits an allow-list entry into scheme / host / path WITHOUT using URL(),
 * which rejects the wildcards we specifically need to inspect.
 */
export function splitEntry(entry: string): EntryParts {
  const schemeMatch = /^([a-z][a-z0-9+.-]*):\/\//i.exec(entry);
  const scheme = schemeMatch ? schemeMatch[1].toLowerCase() : null;
  const rest = schemeMatch ? entry.slice(schemeMatch[0].length) : entry;
  const slash = rest.indexOf("/");
  return {
    scheme,
    host: slash === -1 ? rest : rest.slice(0, slash),
    path: slash === -1 ? "" : rest.slice(slash),
  };
}

/**
 * Hosts where anyone can obtain a subdomain for free, in minutes. A wildcard
 * over one of these is not "slightly loose" — it is an open door, because the
 * attacker can simply deploy to the pattern and satisfy it.
 */
const SHARED_SUBDOMAIN_HOSTS =
  /(^|\.)(vercel\.app|netlify\.app|pages\.dev|fly\.dev|onrender\.com|railway\.app|herokuapp\.com|github\.io|web\.app|firebaseapp\.com|workers\.dev|surge\.sh|glitch\.me|ngrok(-free)?\.app|ngrok\.io|trycloudflare\.com|loca\.lt|replit\.(app|dev))$/;

const LOCAL_HOST_RE = /^(localhost|127\.0\.0\.1|\[::1\]|0\.0\.0\.0)(:\d+)?$/i;

/** Whether a redirect allow-list host is local (localhost, 127.0.0.1 and
 * similar). */
export function isLocalEntry(host: string): boolean {
  return LOCAL_HOST_RE.test(host);
}

/**
 * Dangerous entries in the redirect allow-list.
 *
 * Deliberately silent on the patterns Supabase itself recommends: a wildcard in
 * the PATH (`https://app.example.com/**`) is the documented way to accept any
 * post-login route, and localhost entries are required for local development.
 * Only the HOST is treated as security-relevant, because the host is what
 * decides who receives the token.
 */
export function analyzeRedirectAllowList(config: SupabaseAuthConfig): GithubFinding[] {
  const entries = parseAllowList(readString(config, ALLOW_LIST_KEYS));
  const findings: GithubFinding[] = [];
  const seen = new Set<string>();

  const push = (id: string, severity: GithubFinding["severity"], title: string, consequence: string) => {
    if (seen.has(id)) return;
    seen.add(id);
    findings.push(f(id, severity, title, consequence));
  };

  for (const entry of entries) {
    const { scheme, host, path } = splitEntry(entry);

    // A bare `*` / `**` with no host part at all authorises every URL there is.
    if (entry === "*" || entry === "**" || host === "*" || host === "**" || host === "") {
      push(
        "auth_redirect:wildcard_any_host",
        "CRITICAL",
        `Your login redirect allow-list contains "${entry}", which permits ANY destination`,
        `Supabase's redirect allow-list includes "${entry}". After a successful sign-in, Supabase will hand the user's session to any URL an attacker chooses. ` +
          `The attack is one link: send someone a genuine login link for your app with the redirect pointed at a server you control, let them log in normally on your real domain (2FA and all) and receive their session tokens. ` +
          `Nothing looks like phishing to the victim, because nothing about the login was fake. This is full account takeover for any user who clicks. ` +
          `Fix: remove this entry and list your exact redirect URLs instead (a wildcard in the PATH, like https://yourapp.com/**, is fine; the problem is the host).`
      );
      continue;
    }

    // `**` anywhere in the host crosses dots and slashes, so it matches hosts
    // that have nothing to do with the intended domain.
    if (host.includes("**")) {
      push(
        `auth_redirect:globstar_host:${entry}`,
        "CRITICAL",
        `Login redirect allow-list entry "${entry}" matches hosts you don't own`,
        `The entry "${entry}" puts a "**" in the HOST portion. In Supabase's matching rules "**" matches any characters at all, including dots and slashes, so this does not mean "my subdomains", it means hosts that merely contain your domain name somewhere, including ones an attacker controls. ` +
          `That lets an attacker receive a real user's session after a completely genuine login on your site. ` +
          `Fix: use a single "*" for one subdomain level, or list exact hosts. Keep wildcards to the path.`
      );
      continue;
    }

    if (host.includes("*") || host.includes("?")) {
      const bareHost = host.replace(/^\*\./, "").replace(/:\d+$/, "");
      const shared = SHARED_SUBDOMAIN_HOSTS.test(bareHost);

      push(
        `auth_redirect:wildcard_host:${entry}`,
        shared ? "CRITICAL" : "WARNING",
        shared
          ? `Login redirect allow-list entry "${entry}" lets ANYONE receive your users' sessions`
          : `Login redirect allow-list entry "${entry}" trusts every subdomain`,
        shared
          ? `The entry "${entry}" wildcards a host on ${bareHost}, where anyone can create a subdomain for free in about a minute. ` +
            `An attacker deploys anything to a name matching that pattern, sends a user a genuine login link for your app pointing there, and collects their session after they log in legitimately on your real domain. ` +
            `This is usually left over from wanting preview deployments to work. ` +
            `Fix: remove it, and list the exact preview URLs you actually need, or point previews at a domain you control.`
          : `The entry "${entry}" allows any subdomain to receive a signed-in user's session. That is safe only while you control every subdomain, forever. ` +
            `It commonly breaks in one specific way: a DNS record left pointing at a service you no longer use lets someone else claim that subdomain (a subdomain takeover), and they can then collect sessions from real logins on your real domain. ` +
            `Fix: list the exact hosts you redirect to. If this exists for preview deployments, prefer listing them explicitly.`
      );
      continue;
    }

    // Plaintext transport for a real host: the token is in the URL.
    if (scheme === "http" && !isLocalEntry(host)) {
      push(
        `auth_redirect:insecure_scheme:${entry}`,
        "WARNING",
        `Login redirect allow-list entry "${entry}" sends sessions over plain HTTP`,
        `"${entry}" uses http:// rather than https://, so the session handed over after login travels unencrypted. Anyone between your user and that host (on shared Wi-Fi, or anywhere along the path) can read the tokens and use them. ` +
          `Fix: change it to https://. (http:// on localhost is fine and is not flagged.)` +
          (path ? "" : "")
      );
    }
  }

  return findings;
}

/**
 * Site URL — the default destination for password resets and email
 * confirmations. Not strictly a redirect check, but it comes from the same config and the same
 * two mistakes recur, both of which break real users rather than theoretically.
 */
export function analyzeSiteUrl(config: SupabaseAuthConfig): GithubFinding[] {
  const raw = (readString(config, SITE_URL_KEYS) ?? "").trim();
  if (!raw) return [];

  const { scheme, host } = splitEntry(raw);

  if (isLocalEntry(host)) {
    return [
      f(
        "auth_site_url:localhost",
        "WARNING",
        "Your Site URL still points at localhost",
        `Supabase's Site URL is "${raw}", which is the default and was never changed. Site URL is where password-reset and email-confirmation links point when the code doesn't say otherwise, so those emails are currently sending your users to their own machine, where nothing is running. ` +
          `The practical effect is that password reset appears broken for everyone, and a user who can't reset a password often reuses one or contacts support to have it changed, which is its own risk. ` +
          `Fix: set Site URL to your production URL in Authentication → URL Configuration.`
      ),
    ];
  }

  if (scheme === "http") {
    return [
      f(
        "auth_site_url:insecure_scheme",
        "WARNING",
        "Your Site URL uses plain HTTP",
        `Supabase's Site URL is "${raw}", over http:// rather than https://. Password-reset and confirmation links sent to your users therefore point at an unencrypted page, and the token in those links can be read in transit and used before the real user gets there. ` +
          `Fix: change it to https:// in Authentication → URL Configuration.`
      ),
    ];
  }

  return [];
}

/**
 * Aggregate — one call for the run orchestrator.
 *
 * A null config means the fetch failed. That is "we learned nothing", NOT a
 * clean bill of health, and it returns no findings for the same reason a DNS
 * timeout doesn't become a missing-SPF finding: absence of evidence is not
 * evidence of absence.
 */
export function scanAuthConfig(config: SupabaseAuthConfig | null): GithubFinding[] {
  if (!config) return [];

  if (isUnrecognisedConfigShape(config)) {
    // Deliberately loud. This is the shape of the bug that hid two advisor lints
    // for months, and it must never again present as a passing check.
    console.error(
      "[authConfigScan] auth config had none of the expected keys: B7 and Site URL checks did NOT run. Keys seen:",
      Object.keys(config).slice(0, 40).join(", ")
    );
    return [];
  }

  return [...analyzeRedirectAllowList(config), ...analyzeSiteUrl(config)];
}
