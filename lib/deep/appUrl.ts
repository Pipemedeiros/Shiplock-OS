/**
 * A repository's GitHub homepage, as the app address to suggest.
 *
 * The outside view (the shipped bundle, exposed paths) runs only when
 * ShipLock knows where the app is served, and the GitHub first onboarding
 * never asked. GitHub already carries the homepage a founder set on the
 * repository; this turns it into an origin the founder can confirm. It is
 * only ever a suggestion: nothing is probed until the founder confirms it,
 * and the confirmed address passes the SSRF guard before any request.
 */
const NOT_THE_APP = /(^|\.)(github\.com|gitlab\.com|bitbucket\.org|npmjs\.com|npmjs\.org|pypi\.org|crates\.io|youtube\.com|twitter\.com|x\.com|linkedin\.com|medium\.com|notion\.site|dev\.to)$/i;

export function suggestAppUrl(homepage: string | null | undefined): string | null {
  const raw = homepage?.trim();
  if (!raw || /\s/.test(raw)) return null;
  const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(raw) ? raw : `https://${raw}`;
  let url: URL;
  try { url = new URL(withScheme); } catch { return null; }
  if (url.protocol !== "https:" || url.username || url.password || url.port) return null;
  const host = url.hostname.toLowerCase();
  if (!host.includes(".") || host === "localhost" || host.endsWith(".local") || host.endsWith(".localhost")) return null;
  // An address, not a name: never a homepage worth probing.
  if (/^[\d.]+$/.test(host) || host.includes(":")) return null;
  if (NOT_THE_APP.test(host)) return null;
  return url.origin;
}
