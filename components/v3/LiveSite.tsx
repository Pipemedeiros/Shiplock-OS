import Link from "next/link";
import type { LiveReach } from "@/lib/chain/liveReach";
import type { ShadowRoutes } from "@/lib/chain/shadowRoutes";

// The outside view on Coverage (G3): what ShipLock read from the founder's
// live site, and the backend addresses it requests that the bound repository
// declares no route for (lib/chain/shadowRoutes.ts). Those are surface no code
// was read for, so they read as not checked; an empty list says what it
// covered, never that nothing is there.
const utc = (iso: string) => iso.slice(0, 16).replace("T", " ") + " UTC";

export function liveSiteStatus(live: LiveReach | null, shadow: ShadowRoutes): string {
  if (!live) return "Not bound";
  if (shadow.state === "unknown") return "Unknown";
  if (shadow.paths.length > 0) return `${shadow.paths.length} not in the repository`;
  return shadow.partial ? "Partly read" : "All in the repository";
}

export function LiveSite({ live, repository, shadow }: { live: LiveReach | null; repository: string | null; shadow: ShadowRoutes }) {
  if (!live || !repository) {
    return (
      <p className="v3-small">
        No app address is bound to a selected repository. Bind one under <Link href="/dashboard/settings">Settings, Your app</Link> and
        ShipLock reads what your live site ships, the way a visitor gets it.
      </p>
    );
  }
  const { pages, scriptsSeen, scriptsRead } = live.read;
  const scripts = scriptsSeen !== null && scriptsRead !== null ? `${scriptsRead} of ${scriptsSeen} scripts` : "scripts read unknown";
  return (
    <div className="v3-small">
      <p style={{ marginBottom: 12 }}>
        Read <strong>{live.host}</strong>
        {live.observedAt ? <>, <time dateTime={live.observedAt}>{utc(live.observedAt)}</time></> : null}
        {": "}{pages !== null ? `${pages} ${pages === 1 ? "page" : "pages"}, ` : ""}{scripts}.
        {shadow.state === "read" && shadow.partial ? " Addresses in the rest are unknown." : null}
      </p>
      {shadow.state === "unknown" ? (
        <p>Addresses your live site requests outside {repository}: unknown. {shadow.why}</p>
      ) : shadow.paths.length === 0 ? (
        <p>
          Every backend address your live site requests on its own domain is a route in {repository}. Addresses built at
          runtime and calls to other hosts are not in this list.
        </p>
      ) : (
        <>
          <p style={{ marginBottom: 8 }}>
            Your live site requests {shadow.paths.length === 1 ? "this backend address" : `these ${shadow.paths.length} backend addresses`} on
            its own domain, and {repository} declares no route for {shadow.paths.length === 1 ? "it" : "them"}. A rewrite, another
            service or an older deploy may serve {shadow.paths.length === 1 ? "it" : "them"}. ShipLock read no code
            for {shadow.paths.length === 1 ? "it" : "them"}, so {shadow.paths.length === 1 ? "it is" : "they are"} not checked.
          </p>
          <ul>
            {shadow.paths.map((p) => <li key={p}><code>{p}</code></li>)}
          </ul>
        </>
      )}
    </div>
  );
}
