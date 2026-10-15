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

export type SelfCheck = { method: string; path: string; curl: string; reading: string };

const PARAM = /\[\[?(?:\.\.\.)?[^\]]+\]\]?|:[A-Za-z_]\w*/g;
const READING =
  "Run it against your local or preview app, never production. A 401 or 403 means a sign-in check ran first. A 404 or a 200 means the route reached your data layer without one. A 405 means the route has no handler for that method; try the one it serves. The id does not exist, so nothing is read or changed.";

export function selfCheck(finding: { entry: string; attackClass: string; methods?: string[] }): SelfCheck | null {
  if (finding.attackClass !== "missing_authentication") return null;
  if (!finding.entry.startsWith("/")) return null;
  if (!new RegExp(PARAM.source).test(finding.entry)) return null;
  const methods = (finding.methods ?? []).map((m) => m.toUpperCase());
  const method = methods.length === 0 || methods.includes("GET") ? "GET" : methods[0];
  const path = finding.entry.replace(PARAM, NO_SUCH_ID);
  return { method, path, curl: `curl -i -X ${method} "$APP_URL${path}"`, reading: READING };
}
