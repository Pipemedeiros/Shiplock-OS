import { getSupabaseAdmin } from "@/lib/supabase";

// Which layers of the customer's stack are actually feeding the correlation
// graph, for the dashboard's headline.
//
// This replaces any "% secure" or grade-shaped claim, and the distinction
// matters: a percentage implies we know what fraction of the customer's risk we
// have found, which nobody can know. "4 of 5 layers correlated" is a count of
// what is WIRED UP — verifiable, honest, and it makes the upgrade path legible
// without inventing a threat to scare someone with.
//
// Connected is deliberately measured by "has this layer ever produced facts or
// is its connection live", not by "did it produce a finding". A layer that ran
// and found nothing is working perfectly; conflating that with a layer that
// never ran is the exact mistake migration 042 exists to stop us making in the
// snapshot history.

export type LayerId = "code" | "database" | "runtime" | "traffic" | "email-dns";

export interface LayerState {
  id: LayerId;
  /** Customer-facing name. Named by what it watches, never by how. */
  label: string;
  connected: boolean;
  /** Shown when not connected: what correlating this layer would add. */
  unlocks: string;
}

export interface LayerStatus {
  layers: LayerState[];
  connectedCount: number;
  totalCount: number;
  /** The next layer worth connecting, or null when all are live. */
  nextUp: LayerState | null;
}

/**
 * Read live connection state for one user.
 *
 * Service-role: every column consulted here (github_installation_id,
 * supabase_mgmt_token_encrypted, monitored_app_url) is locked away from
 * `authenticated` by migrations 035/041, and this returns booleans only — the
 * page never receives a token, an installation id, or a URL.
 */
export async function getLayerStatus(userId: string): Promise<LayerStatus> {
  const admin = getSupabaseAdmin();

  const { data: profile } = await admin
    .from("user_profiles")
    .select(
      "github_installation_id, supabase_mgmt_token_encrypted, monitored_project_url, monitored_app_url, vercel_access_token_encrypted"
    )
    .eq("id", userId)
    .maybeSingle();

  // Traffic is the one layer with no connection column: it is live exactly when
  // the optional edge snippet has actually sent us something. Presence of any
  // recent graph fact is the honest test — the snippet can be installed and
  // sending nothing, which is not the same as protecting anything.
  const { data: trafficFacts } = await admin
    .from("graph_facts")
    .select("collector")
    .eq("user_id", userId)
    .eq("collector", "traffic")
    .maybeSingle();

  const layers: LayerState[] = [
    {
      id: "code",
      label: "code",
      connected: Boolean(profile?.github_installation_id),
      unlocks:
        "Connect GitHub and we can tell you whether anything in your code actually depends on a risky policy — the difference between worth a look and fix this today.",
    },
    {
      id: "database",
      label: "database",
      // The 16-check scan alone gives us table-level facts, so a monitored
      // project counts. The Management API connection deepens this layer
      // (policy text, advisors, auth config) but is not what makes it exist.
      connected: Boolean(profile?.monitored_project_url),
      unlocks: "Connect Supabase so we can read your policies, not just probe around them.",
    },
    {
      id: "runtime",
      label: "live config",
      // A provider connection, not a snippet. Connected means we can read what
      // the host says about itself right now, which the repository cannot show:
      // which environment variables exist and where they are scoped.
      connected: Boolean(profile?.vercel_access_token_encrypted),
      unlocks:
        "Connect your host and we can see which environment variables actually exist in production, not only the ones your code expects.",
    },
    {
      id: "traffic",
      label: "traffic",
      connected: Boolean(trafficFacts),
      unlocks:
        "Add the edge snippet and a finding can be ranked by whether anyone is actually knocking on it.",
    },
    {
      id: "email-dns",
      label: "email/DNS",
      connected: Boolean(profile?.monitored_app_url),
      unlocks: "We derive this from your app URL — nothing to connect.",
    },
  ];

  const connectedCount = layers.filter((l) => l.connected).length;

  return {
    layers,
    connectedCount,
    totalCount: layers.length,
    nextUp: layers.find((l) => !l.connected) ?? null,
  };
}

// Re-exported for server-side callers already importing from here; client
// components must import from ./layerLabels directly (see that file's header).
export { correlationLayers } from "./layerLabels";

/**
 * The headline sentence. Pure, so it is unit-testable without a database and
 * so the wording lives in one place rather than being assembled in JSX.
 */
export function describeLayerStatus(status: LayerStatus): string {
  const connected = status.layers.filter((l) => l.connected).map((l) => l.label);
  if (connected.length === 0) {
    return "No layers correlated yet — connect your stack to begin.";
  }
  return `${status.connectedCount} of ${status.totalCount} layers correlated — ${connected.join(", ")}.`;
}
