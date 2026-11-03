/**
 * A safe self-check for one finding: Strix's idea (proof per finding),
 * rebuilt so ShipLock never sends attack traffic itself.
 *
 * The founder or their agent runs one request against their own local or
 * preview app. It names an id that cannot exist, so it reads and changes
 * nothing; the status code alone shows whether a sign-in check ran before the
 * route reached the data layer. Offered only where one anonymous request can
 * show the gap: a route with a dynamic segment and a missing sign-in check.
 * Authorization gaps need a second account, and server actions and tRPC
 * procedures have no plain URL, so they get none.
 */
export const NO_SUCH_ID = "00000000-0000-4000-8000-000000000000";

type SelfCheck = { method: string; path: string; curl: string; reading: string };

const PARAM = /\[\[?(?:\.\.\.)?[^\]]+\]\]?|:[A-Za-z_]\w*/g;
const READING =
  "Run it against your local or preview app, never production. A 401 or 403 means a sign-in check ran first. A 404 or a 200 means the route reached your data layer without one. A 405 means the route has no handler for that method; try the one it serves. The id does not exist, so nothing is read or changed.";

/** The methods to try, from the audit's stored route facts: those that never
 * refuse an anonymous caller, else those the file exports, else none (GET). */
export function checkMethods(route: { methods?: string[]; unrefusedMethods?: string[] } | undefined): string[] {
  if (route?.unrefusedMethods?.length) return route.unrefusedMethods;
  return route?.methods ?? [];
}

/** One harmless request the customer can run against their own app to check a
 * missing sign-in finding, or null when none applies. */
export function selfCheck(finding: { entry: string; attackClass: string; methods?: string[] }): SelfCheck | null {
  if (finding.attackClass !== "missing_authentication") return null;
  if (!finding.entry.startsWith("/")) return null;
  if (!new RegExp(PARAM.source).test(finding.entry)) return null;
  const methods = (finding.methods ?? []).map((m) => m.toUpperCase());
  const method = methods.length === 0 || methods.includes("GET") ? "GET" : methods[0];
  const path = finding.entry.replace(PARAM, NO_SUCH_ID);
  return { method, path, curl: `curl -i -X ${method} "$APP_URL${path}"`, reading: READING };
}

/**
 * What a reported status means, for a self-check the customer's agent ran
 * and reported over MCP (report_self_check, migration 107). Agent output is
 * untrusted: this is "the test ran and the agent says it got N", never
 * proof and never a status change (only lib/proving earns proven).
 */
type SelfCheckOutcome = "check_ran" | "redirected" | "reached" | "wrong_method" | "inconclusive";

/** What the status the customer reported from the self-check means. */
export function readSelfCheck(status: number): { outcome: SelfCheckOutcome; meaning: string } {
  if (status === 401 || status === 403) return { outcome: "check_ran", meaning: "a sign-in check ran before the route reached data, so the gap may not hold there" };
  if (status >= 300 && status < 400) return { outcome: "redirected", meaning: "a redirect, often to sign in; the Location header says where" };
  if (status === 404 || (status >= 200 && status < 300)) return { outcome: "reached", meaning: "the route reached the data layer without a sign-in check" };
  if (status === 405) return { outcome: "wrong_method", meaning: "the route has no handler for that method, so the check did not test it" };
  return { outcome: "inconclusive", meaning: "this status does not show either way" };
}

const HOST = /^[a-z0-9.-]{1,253}(:[0-9]{1,5})?$/;

/** The host:port an agent ran against, from a URL or a bare host, or null. */
export function reportedHost(value: string): string | null {
  try {
    const url = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(value) ? value : `http://${value}`);
    if (url.username || url.password || !/^https?:$/.test(url.protocol)) return null;
    return HOST.test(url.host) ? url.host : null;
  } catch { return null; }
}
