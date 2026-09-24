import type { GatewayState, TrafficSourceStatus } from "@/lib/traffic/sourceStatus";
import type { HotRouteOffer } from "@/lib/traffic/hotRoutes";
import { RateLimitOffers } from "./RateLimitButton";

// Per repository, where ShipLock's traffic view comes from (Q3). No source is
// said plainly, never shown as quiet.
const utc = (iso: string) => iso.slice(0, 16).replace("T", " ") + " UTC";

function gatewayLine(item: TrafficSourceStatus): string | null {
  const text: Record<GatewayState, string | null> = {
    read: item.observedAt ? `Supabase gateway log read ${utc(item.observedAt)}.` : null,
    unread: `The Supabase gateway log could not be read${item.observedAt ? ` at ${utc(item.observedAt)}` : ""}.`,
    never_read: "Supabase gateway log linked, not read yet.",
    unbound: "Supabase is connected but not linked to this repository.",
    not_enabled: "Traffic observation is not enabled for this account.",
    not_connected: null,
  };
  return text[item.gateway];
}

export function TrafficSources({ sources, offers = {} }: {
  sources: { available: boolean; items: TrafficSourceStatus[] }; offers?: Record<string, HotRouteOffer[]>;
}) {
  if (!sources.available) return <p>We could not load traffic sources. Whether any traffic is read is unknown.</p>;
  if (sources.items.length === 0) return <p className="v3-small">Select a repository first; traffic is shown per repository.</p>;
  return (
    <ul className="v3-small">
      {sources.items.map((item) => {
        const gateway = gatewayLine(item);
        return (
          <li key={item.repositoryId} style={{ marginBottom: 12 }}>
            <strong>{item.repository}</strong>
            {item.sites > 0 ? <><br />{item.sites} snippet {item.sites === 1 ? "site" : "sites"} sending request metadata.</> : null}
            {gateway ? <><br />{gateway}</> : null}
            {!item.hasSource ? <><br />No traffic source: ShipLock sees no traffic for this repository.</> : null}
            <RateLimitOffers repositoryId={item.repositoryId} offers={offers[item.repositoryId] ?? []} />
          </li>
        );
      })}
    </ul>
  );
}
